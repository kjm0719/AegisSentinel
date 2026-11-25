using System.Net;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using AegisSentinel.Core.Models;
using AegisSentinel.Core.Services;

namespace AegisSentinel.Core.Engine;

/// <summary>
/// Real-time ETW subscriber for Microsoft-Windows-DNS-Client (Event IDs 3006/3008/3020).
/// Captures DNS queries and resolved IPs in real time with ZERO PowerShell polling,
/// enabling pre-connection IOC domain detection and instant IP-to-Domain correlation.
/// </summary>
public sealed class EtwDnsTelemetryService : IDisposable
{
    private const string SessionName = "AegisSentinelDnsTelemetry";
    private static readonly Guid DnsClientProviderGuid = new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");

    private readonly ProcessController _processController;
    private readonly NetworkGuardMonitor _networkGuard;
    private readonly Func<GuardPolicy> _policyProvider;
    private readonly TelemetryMetrics? _metrics;

    private TraceEventSession? _session;
    private Thread? _listenerThread;
    private Timer? _flushTimer;
    private volatile bool _running;

    public bool IsRunning => _running;
    public event Action<SecurityEvent>? ThreatDetected;

    public EtwDnsTelemetryService(
        ProcessController processController,
        NetworkGuardMonitor networkGuard,
        Func<GuardPolicy> policyProvider,
        TelemetryMetrics? metrics = null)
    {
        _processController = processController;
        _networkGuard = networkGuard;
        _policyProvider = policyProvider;
        _metrics = metrics;
    }

    public bool Start()
    {
        if (!ProcessController.IsCurrentProcessElevated()) return false;

        Stop();

        try
        {
            var existing = TraceEventSession.GetActiveSession(SessionName);
            existing?.Stop(true);
        }
        catch { }

        try
        {
            var session = new TraceEventSession(SessionName)
            {
                StopOnDispose = true,
                BufferSizeMB = 4
            };
            _session = session;

            session.Source.Dynamic.All += OnDnsEvent;
            session.EnableProvider(DnsClientProviderGuid, TraceEventLevel.Informational);

            _running = true;
            int dnsFlushTick = 0;
            _flushTimer = new Timer(_ =>
            {
                int tick = Interlocked.Increment(ref dnsFlushTick);
                if (PowerProfileHelper.IsOnBatteryPower && (tick & 1) == 1)
                {
                    return; // 3.0s effective cadence on laptop battery, 1.5s on AC
                }
                try { session.Flush(); } catch { }
            }, null, TimeSpan.FromMilliseconds(1500), TimeSpan.FromMilliseconds(1500));

            _listenerThread = new Thread(() =>
            {
                try
                {
                    session.Source.Process();
                }
                catch { }
                finally
                {
                    if (ReferenceEquals(_session, session))
                    {
                        _running = false;
                    }
                }
            })
            {
                IsBackground = true,
                Name = "AegisSentinel-ETW-DNS"
            };
            _listenerThread.Start();
            return true;
        }
        catch
        {
            Stop();
            return false;
        }
    }

    public void Stop()
    {
        _running = false;
        _flushTimer?.Dispose();
        _flushTimer = null;

        try
        {
            _session?.Stop(true);
            _session?.Dispose();
        }
        catch { }
        finally
        {
            _session = null;
        }

        var thread = _listenerThread;
        _listenerThread = null;
        if (thread is { IsAlive: true } && thread != Thread.CurrentThread)
        {
            try { thread.Join(1500); } catch { }
        }
    }

    private void OnDnsEvent(TraceEvent data)
    {
        // 3006 = Query Initiated, 3008 = Query Completed, 3020 = Wire Query Response (runs inside Dnscache svchost.exe!)
        int eventId = (int)data.ID;
        if (eventId is not (3006 or 3008 or 3020)) return;
        _metrics?.IncrementDnsEvent();

        try
        {
            var queryName = data.PayloadByName("QueryName")?.ToString()?.Trim().TrimEnd('.');
            if (string.IsNullOrWhiteSpace(queryName)) return;

            var queryResults = data.PayloadByName("QueryResults")?.ToString();
            if (!string.IsNullOrWhiteSpace(queryResults))
            {
                foreach (var ip in ParseDnsResultIps(queryResults))
                {
                    _networkGuard.RecordDnsResolution(queryName, ip);
                }
            }

            // Event 3020 executes inside the Windows Dnscache service (svchost.exe), NOT the originating client process!
            // Only evaluate client-originated query events (3006 / 3008), and fast-reject uninteresting domains BEFORE OpenProcess syscalls!
            if (eventId == 3020 || !_networkGuard.IsPotentiallyInterestingDomain(queryName))
            {
                return;
            }

            int pid = data.ProcessID;
            if (pid <= 4 || pid == Environment.ProcessId || InternalHelperProcessRegistry.IsInternalHelper(pid))
            {
                return;
            }

            var procPath = _processController.GetExecutablePath(pid);
            var procName = !string.IsNullOrWhiteSpace(procPath)
                ? Path.GetFileNameWithoutExtension(procPath)
                : _processController.GetProcessNameSafe(pid);

            // Never blame the Windows Dnscache svchost.exe resolver itself for cached/DoH DNS resolution
            if (procName.Equals("svchost", StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrWhiteSpace(procPath) &&
                QuarantineManager.IsProtectedSystemOrSelfPath(procPath))
            {
                return;
            }

            var policy = _policyProvider();
            var alert = _networkGuard.EvaluateDnsQuery(pid, procName, procPath, queryName, policy);
            if (alert is not null)
            {
                ThreatDetected?.Invoke(alert);
            }
        }
        catch { }
    }

    public static IReadOnlyList<string> ParseDnsResultIps(string rawResults)
    {
        var ips = new List<string>();
        if (string.IsNullOrWhiteSpace(rawResults)) return ips;

        foreach (var part in rawResults.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var token = part.Trim();
            if (token.StartsWith("type:", StringComparison.OrdinalIgnoreCase))
            {
                var lastSpace = token.LastIndexOf(' ');
                if (lastSpace > 0) token = token[(lastSpace + 1)..].Trim();
            }

            if ((token.Contains('.') || token.Contains(':')) && IPAddress.TryParse(token, out var parsed))
            {
                if (parsed.IsIPv4MappedToIPv6) parsed = parsed.MapToIPv4();
                ips.Add(parsed.ToString());
            }
        }

        return ips;
    }

    public void Dispose()
    {
        Stop();
    }
}
