using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using AegisSentinel.Core.Models;
using AegisSentinel.Core.Native;
using AegisSentinel.Core.Services;

namespace AegisSentinel.Core.Engine;

/// <summary>
/// Monitors outbound TCP connections (ETW when elevated, IP Helper API fallback),
/// correlates IPs with Windows DNS cache &amp; Threat Intelligence IOCs, and surfaces live connections.
/// </summary>
public sealed class NetworkGuardMonitor : IDisposable
{
    private static readonly HashSet<string> NetworkSuspiciousLolBins = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "tinyget.exe",
        "luajit.exe"
    };

    private static readonly HashSet<int> HighRiskC2Ports = new()
    {
        1337, 4444, 4445, 5555, 6667, 6697, 8888, 9001, 9050, 31337
    };

    // Common HTTPS (443) exfiltration / C2 abuse services used by modern AI infostealers & North Korean APTs (Kimsuky / Lazarus)
    private static readonly string[] ExfiltrationAbuseDomains =
    {
        "api.telegram.org",
        "trycloudflare.com",
        "ngrok-free.app",
        "ngrok.io",
        "webhook.site",
        "paste.ee",
        "transfer.sh",
        "discordapp.com",
        "ps.pndsn.com",
        "api.pcloud.com",
        "cloud-api.yandex.net",
        "dl.dropboxusercontent.com"
    };

    // Cloud storage domains abused by Kimsuky LOLBins (powershell/mshta/wscript/certutil) for stage-2 payload retrieval
    private static readonly string[] LolBinCloudStageDomains =
    {
        "raw.githubusercontent.com",
        "gist.githubusercontent.com",
        "api.dropboxapi.com",
        "drive.google.com"
    };

    private static readonly HashSet<string> StandardBrowserBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe", "whale.exe",
        "discord.exe", "telegram.exe", "dropbox.exe", "googledrivesfs.exe", "ngrok.exe", "cloudflared.exe"
    };

    private readonly ProcessController _processController;
    private readonly SignatureVerifier _signatureVerifier;
    private readonly BehaviorRiskEngine _riskEngine;
    private readonly ThreatIntelStore _intelStore;

    public bool IsPotentiallyInterestingDomain(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return false;
        var clean = domain.Trim().TrimEnd('.');
        if (clean.Length == 0) return false;
        if (_intelStore.IsDomainBlocked(clean)) return true;
        return ExfiltrationAbuseDomains.Any(d =>
                   clean.Equals(d, StringComparison.OrdinalIgnoreCase) ||
                   clean.EndsWith("." + d, StringComparison.OrdinalIgnoreCase)) ||
               LolBinCloudStageDomains.Any(d =>
                   clean.Equals(d, StringComparison.OrdinalIgnoreCase) ||
                   clean.EndsWith("." + d, StringComparison.OrdinalIgnoreCase));
    }
    private readonly Func<GuardPolicy> _policyProvider;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _seenConnections = new();
    private readonly ConcurrentDictionary<string, string> _ipToDomainCache = new(StringComparer.OrdinalIgnoreCase);
    private Timer? _pollTimer;
    private Timer? _dnsTimer;
    private int _isPolling;
    private int _isRefreshingDns;

    public event Action<SecurityEvent>? ThreatDetected;

    public NetworkGuardMonitor(
        ProcessController processController,
        SignatureVerifier signatureVerifier,
        BehaviorRiskEngine riskEngine,
        ThreatIntelStore intelStore,
        Func<GuardPolicy> policyProvider)
    {
        _processController = processController;
        _signatureVerifier = signatureVerifier;
        _riskEngine = riskEngine;
        _intelStore = intelStore;
        _policyProvider = policyProvider;
    }

    public void Start(bool etwHandlesNetwork, bool etwHandlesDns = false)
    {
        Stop();

        // Only use fallback PowerShell DNS cache poller when real-time ETW DNS is unavailable
        if (!etwHandlesDns)
        {
            _dnsTimer = new Timer(_ => RefreshDnsCache(), null, TimeSpan.FromSeconds(8), TimeSpan.FromMinutes(2));
        }

        if (!etwHandlesNetwork)
        {
            _pollTimer = new Timer(_ => PollTcpTable(), null, TimeSpan.FromSeconds(2), TimeSpan.FromMilliseconds(1500));
        }
    }

    public void RecordDnsResolution(string domain, string ip)
    {
        if (string.IsNullOrWhiteSpace(domain) || string.IsNullOrWhiteSpace(ip)) return;
        if (_ipToDomainCache.Count > 8192) _ipToDomainCache.Clear();
        _ipToDomainCache[ip.Trim()] = domain.Trim().TrimEnd('.');
    }

    /// <summary>
    /// Pre-connection DNS telemetry check (fed directly by Microsoft-Windows-DNS-Client ETW).
    /// Catches IOC C2 domains and LOLBin exfiltration channels BEFORE the TCP handshake finishes!
    /// </summary>
    public SecurityEvent? EvaluateDnsQuery(
        int pid,
        string processName,
        string processPath,
        string domain,
        GuardPolicy policy,
        SignatureInfo? signatureOverride = null)
    {
        if (!policy.EnableNetworkGuard ||
            pid <= 4 ||
            pid == Environment.ProcessId ||
            InternalHelperProcessRegistry.IsInternalHelper(pid) ||
            ProcessRuleEvaluator.IsProtectedHostIdeProcess(processPath) ||
            string.IsNullOrWhiteSpace(domain))
        {
            return null;
        }

        var cleanDomain = domain.Trim().TrimEnd('.');
        var dedupKey = $"DNS|{pid}|{cleanDomain}";
        var now = DateTimeOffset.UtcNow;
        if (_seenConnections.TryGetValue(dedupKey, out var lastSeen) && (now - lastSeen).TotalSeconds < 60)
        {
            return null;
        }

        var exeName = Path.GetFileName(string.IsNullOrWhiteSpace(processPath) ? processName : processPath);
        if (!exeName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(exeName))
        {
            exeName += ".exe";
        }

        var sig = signatureOverride ?? (File.Exists(processPath)
            ? _signatureVerifier.VerifyFile(processPath)
            : new SignatureInfo(SignatureStatus.Unknown, string.Empty));
        bool isTrustedBrowserOrClient = StandardBrowserBinaries.Contains(exeName) &&
                                        (sig.IsSigned || !ProcessRuleEvaluator.IsHighRiskDropPath(processPath));

        if (_intelStore.IsDomainBlocked(cleanDomain))
        {
            if (_seenConnections.Count > 4096) _seenConnections.Clear();
            _seenConnections[dedupKey] = now;
            // If a standard signed browser merely resolves an embedded link on a URLhaus domain, log at Medium (50) without freezing Chrome!
            int dnsIocWeight = (isTrustedBrowserOrClient || sig.Status == SignatureStatus.TrustedMicrosoft) ? 50 : 95;
            var assess = _riskEngine.RecordSignal(pid, "ThreatIntelC2Match", dnsIocWeight, marksExternalNetwork: true, smartLowFrictionMode: policy.SmartLowFrictionMode);
            return new SecurityEvent
            {
                Severity = assess.TotalScore >= 75 ? ThreatSeverity.Critical : ThreatSeverity.High,
                Category = ThreatCategory.NetworkAnomaly,
                ActionTaken = SecurityActionTaken.Logged,
                Title = $"실시간 ETW DNS: 악성 IOC 도메인 조회 차단 ({cleanDomain})",
                Description = $"'{exeName}' (PID {pid})가 연결 직전 단계에서 차단 도메인 '{cleanDomain}'을(를) DNS 조회했습니다.",
                ProcessId = pid,
                ProcessName = processName,
                ProcessPath = processPath,
                RemoteDomain = cleanDomain,
                TargetPath = processPath,
                RiskScore = assess.TotalScore,
                RiskSignals = assess.Signals.ToList(),
                Signature = sig,
                IsRiskAlreadyCorrelated = true
            };
        }

        if (!string.IsNullOrWhiteSpace(processPath) &&
            policy.WhitelistedExecutablePaths.Contains(processPath, StringComparer.OrdinalIgnoreCase))
        {
            return null;
        }

        bool isLolBin = NetworkSuspiciousLolBins.Contains(exeName);
        bool isUnsignedDropper = !sig.IsSigned && ProcessRuleEvaluator.IsHighRiskDropPath(processPath);
        bool isExfilChannel = ExfiltrationAbuseDomains.Any(d =>
                                  cleanDomain.Equals(d, StringComparison.OrdinalIgnoreCase) ||
                                  cleanDomain.EndsWith("." + d, StringComparison.OrdinalIgnoreCase));
        bool isCloudStage = (isLolBin || isUnsignedDropper) && LolBinCloudStageDomains.Any(d =>
                                  cleanDomain.Equals(d, StringComparison.OrdinalIgnoreCase) ||
                                  cleanDomain.EndsWith("." + d, StringComparison.OrdinalIgnoreCase));
        bool isAbuseDomain = !isTrustedBrowserOrClient && (isExfilChannel || isCloudStage);

        if (!isAbuseDomain)
        {
            return null;
        }

        if (_seenConnections.Count > 4096) _seenConnections.Clear();
        _seenConnections[dedupKey] = now;
        int weight = !sig.IsSigned ? 80 : (isExfilChannel && isLolBin ? 75 : 55);
        // Share the exact same signal name ("HttpsExfilAbuseChannel" / "LolBinExternalNetwork") with EvaluateOutboundConnection
        // so DNS + TCP to the same channel 10ms apart NEVER double-count (55 + 55 = 100) and falsely freeze signed apps!
        string dnsSigName = isExfilChannel ? "HttpsExfilAbuseChannel" : "LolBinExternalNetwork";
        var exfilAssess = _riskEngine.RecordSignal(pid, dnsSigName, weight, marksExternalNetwork: true, smartLowFrictionMode: policy.SmartLowFrictionMode);
        return new SecurityEvent
        {
            Severity = exfilAssess.TotalScore >= 75 ? ThreatSeverity.Critical : ThreatSeverity.High,
            Category = ThreatCategory.Exfiltration,
            ActionTaken = SecurityActionTaken.Logged,
            Title = $"실시간 ETW DNS: 의심 유출/클라우드 C2 도메인 조회 ({cleanDomain})",
            Description = $"'{exeName}' (PID {pid})가 비브라우저 유출/C2 채널 도메인 '{cleanDomain}'을(를) 조회했습니다.",
            ProcessId = pid,
            ProcessName = processName,
            ProcessPath = processPath,
            RemoteDomain = cleanDomain,
            TargetPath = processPath,
            RiskScore = exfilAssess.TotalScore,
            RiskSignals = exfilAssess.Signals.ToList(),
            Signature = sig,
            IsRiskAlreadyCorrelated = true
        };
    }

    public void Stop()
    {
        _pollTimer?.Dispose();
        _pollTimer = null;
        _dnsTimer?.Dispose();
        _dnsTimer = null;
        _seenConnections.Clear();
    }

    public string ResolveCachedDomain(string ip)
    {
        return _ipToDomainCache.TryGetValue(ip, out var domain) ? domain : string.Empty;
    }

    public IReadOnlyList<ActiveNetworkConnection> GetActiveExternalConnections()
    {
        var list = new List<ActiveNetworkConnection>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (pid, remoteIp, remotePort) in EnumerateActiveTcpConnections())
        {
            if (pid <= 4 || IsLocalOrPrivateIp(remoteIp))
            {
                continue;
            }

            var ipStr = remoteIp.ToString();
            var key = $"{pid}|{ipStr}:{remotePort}";
            if (!seen.Add(key)) continue;

            var path = _processController.GetExecutablePath(pid);
            var name = !string.IsNullOrWhiteSpace(path)
                ? Path.GetFileNameWithoutExtension(path)
                : _processController.GetProcessNameSafe(pid);
            var sig = File.Exists(path)
                ? _signatureVerifier.VerifyFile(path)
                : new SignatureInfo(SignatureStatus.Unknown, string.Empty);

            list.Add(new ActiveNetworkConnection(
                pid,
                name,
                path,
                ipStr,
                remotePort,
                ResolveCachedDomain(ipStr),
                sig.DisplayLabel,
                _riskEngine.GetCurrentScore(pid)));
        }

        return list.OrderByDescending(c => c.RiskScore).ThenBy(c => c.ProcessName).ToList();
    }

    public SecurityEvent? EvaluateOutboundConnection(
        int pid,
        string processName,
        string processPath,
        IPAddress remoteIp,
        int remotePort,
        GuardPolicy policy,
        SignatureInfo? signatureOverride = null,
        string? domainOverride = null)
    {
        if (!policy.EnableNetworkGuard ||
            pid <= 4 ||
            pid == Environment.ProcessId ||
            InternalHelperProcessRegistry.IsInternalHelper(pid) ||
            ProcessRuleEvaluator.IsProtectedHostIdeProcess(processPath))
        {
            return null;
        }

        if (IsLocalOrPrivateIp(remoteIp))
        {
            return null;
        }

        var ipStr = remoteIp.ToString();
        var domain = domainOverride ?? ResolveCachedDomain(ipStr);
        var endpoint = $"{ipStr}:{remotePort}";
        bool hadCredentialAccess = _riskEngine.HasAccessedCredentials(pid);
        var dedupKey = hadCredentialAccess ? $"EXFIL|{pid}|{endpoint}" : $"{pid}|{endpoint}";
        var now = DateTimeOffset.UtcNow;
        if (_seenConnections.TryGetValue(dedupKey, out var lastSeen) && (now - lastSeen).TotalMinutes < 30)
        {
            return null;
        }

        var exeName = Path.GetFileName(string.IsNullOrWhiteSpace(processPath) ? processName : processPath);
        if (!exeName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(exeName))
        {
            exeName += ".exe";
        }

        var sig = signatureOverride ?? (File.Exists(processPath)
            ? _signatureVerifier.VerifyFile(processPath)
            : new SignatureInfo(SignatureStatus.Unknown, string.Empty));
        bool isTrustedBrowserOrClient = StandardBrowserBinaries.Contains(exeName) &&
                                        (sig.IsSigned || !ProcessRuleEvaluator.IsHighRiskDropPath(processPath));

        // 0. Threat Intel IOC IP / Domain match:
        // Distinguish explicit user IOCs (always Critical 95) from noisy public feed IPs (_feedIps) when domain is protected or browser/OS
        bool isUserIoc = _intelStore.IsUserIpBlocked(ipStr) || _intelStore.IsDomainBlocked(domain);
        bool isPublicFeedIp = !isUserIoc &&
                              !ThreatIntelStore.IsProtectedDomain(domain) &&
                              _intelStore.IsPublicFeedIpBlocked(ipStr);

        if (isUserIoc || isPublicFeedIp)
        {
            if (_seenConnections.Count > 4096) _seenConnections.Clear();
            _seenConnections[dedupKey] = now;
            int c2Weight = (isPublicFeedIp && (isTrustedBrowserOrClient || sig.Status == SignatureStatus.TrustedMicrosoft) && (remotePort is 80 or 443))
                ? 45
                : ((isUserIoc && isTrustedBrowserOrClient && !_intelStore.IsUserIpBlocked(ipStr)) ? 50 : 95);
            var iocAssess = _riskEngine.RecordSignal(pid, "ThreatIntelC2Match", c2Weight, marksExternalNetwork: true, smartLowFrictionMode: policy.SmartLowFrictionMode);
            return new SecurityEvent
            {
                Severity = iocAssess.TotalScore >= 75 ? ThreatSeverity.Critical : ThreatSeverity.High,
                Category = ThreatCategory.NetworkAnomaly,
                ActionTaken = SecurityActionTaken.Logged,
                Title = $"위협 인텔리전스(IOC) 악성 C2 접속 탐지: {(string.IsNullOrEmpty(domain) ? ipStr : domain)}",
                Description = $"'{exeName}' (PID {pid})가 차단 목록에 등록된 악성 주소 {endpoint} ({domain})에 연결을 시도했습니다.",
                ProcessId = pid,
                ProcessName = processName,
                ProcessPath = processPath,
                RemoteEndpoint = endpoint,
                RemoteDomain = domain,
                TargetPath = processPath,
                RiskScore = iocAssess.TotalScore,
                RiskSignals = iocAssess.Signals.ToList(),
                Signature = sig,
                IsRiskAlreadyCorrelated = true
            };
        }

        if (!string.IsNullOrWhiteSpace(processPath) &&
            policy.WhitelistedExecutablePaths.Contains(processPath, StringComparer.OrdinalIgnoreCase))
        {
            return null;
        }

        bool isLolBin = NetworkSuspiciousLolBins.Contains(exeName);
        bool isUnsignedDropper = !sig.IsSigned && ProcessRuleEvaluator.IsHighRiskDropPath(processPath);
        bool isSuspiciousPort = HighRiskC2Ports.Contains(remotePort) && !sig.IsSigned;
        bool isExfilAbuseDomain = !string.IsNullOrWhiteSpace(domain) &&
                                  !isTrustedBrowserOrClient &&
                                  (ExfiltrationAbuseDomains.Any(d =>
                                      domain.Equals(d, StringComparison.OrdinalIgnoreCase) ||
                                      domain.EndsWith("." + d, StringComparison.OrdinalIgnoreCase)) ||
                                   ((isLolBin || isUnsignedDropper) && LolBinCloudStageDomains.Any(d =>
                                      domain.Equals(d, StringComparison.OrdinalIgnoreCase) ||
                                      domain.EndsWith("." + d, StringComparison.OrdinalIgnoreCase))));

        if (!isLolBin && !isUnsignedDropper && !isSuspiciousPort && !isExfilAbuseDomain && !hadCredentialAccess)
        {
            return null;
        }

        if (_seenConnections.Count > 4096) _seenConnections.Clear();
        _seenConnections[dedupKey] = now;

        int weight = 30;
        string signalName = "OutboundExternalNetwork";
        string title = "의심스러운 외부 네트워크(C2) 연결 탐지";
        var category = ThreatCategory.NetworkAnomaly;

        if (hadCredentialAccess)
        {
            weight = 50;
            signalName = "PostCredentialExternalConnect";
            title = "자격증명 접근 직후 외부 데이터 유출(Exfiltration) 의심!";
            category = ThreatCategory.Exfiltration;
        }
        else if (isExfilAbuseDomain)
        {
            weight = !sig.IsSigned ? 75 : 55;
            signalName = "HttpsExfilAbuseChannel";
            title = $"비브라우저 프로세스의 HTTPS 유출 채널({domain}) 통신 탐지";
            category = ThreatCategory.Exfiltration;
        }
        else if (isLolBin)
        {
            weight = 55;
            signalName = "LolBinExternalNetwork";
            title = $"시스템 스크립트/LOLBin({exeName})의 외부 통신 탐지";
        }
        else if (isSuspiciousPort)
        {
            weight = 55;
            signalName = "SuspiciousC2Port";
            title = $"미서명 프로세스의 C2 의심 포트({remotePort}) 연결 탐지";
        }
        else if (isUnsignedDropper)
        {
            weight = 45;
            signalName = "UnsignedDropperNetwork";
            title = "임시/다운로드 폴더 미서명 실행 파일의 외부 통신 탐지";
        }

        var assessment = _riskEngine.RecordSignal(
            pid,
            signalName,
            weight,
            marksExternalNetwork: true,
            smartLowFrictionMode: policy.SmartLowFrictionMode);

        var severity = assessment.TotalScore >= 75
            ? ThreatSeverity.Critical
            : (assessment.TotalScore >= 50 ? ThreatSeverity.High : ThreatSeverity.Medium);

        var domainNote = string.IsNullOrWhiteSpace(domain) ? string.Empty : $" ({domain})";
        return new SecurityEvent
        {
            Severity = severity,
            Category = assessment.IsExfiltrationChain ? ThreatCategory.Exfiltration : category,
            ActionTaken = SecurityActionTaken.Logged,
            Title = assessment.IsExfiltrationChain
                ? "자격증명 탈취 + 외부 유출 체인 탐지!"
                : title,
            Description = $"'{exeName}' (PID {pid})가 외부 주소 {endpoint}{domainNote}로 연결했습니다. 누적 위험도: {assessment.TotalScore}/100 ({string.Join(", ", assessment.Signals)})",
            ProcessId = pid,
            ProcessName = processName,
            ProcessPath = processPath,
            RemoteEndpoint = endpoint,
            RemoteDomain = domain,
            TargetPath = processPath,
            RiskScore = assessment.TotalScore,
            RiskSignals = assessment.Signals.ToList(),
            Signature = sig,
            IsRiskAlreadyCorrelated = true
        };
    }

    public static bool IsLocalOrPrivateIp(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any))
        {
            return true;
        }

        if (ip.IsIPv4MappedToIPv6)
        {
            ip = ip.MapToIPv4();
        }

        var bytes = ip.GetAddressBytes();
        if (bytes.Length == 4)
        {
            return bytes[0] == 10 ||
                   bytes[0] == 127 ||
                   bytes[0] == 0 ||
                   (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                   (bytes[0] == 192 && bytes[1] == 168) ||
                   (bytes[0] == 169 && bytes[1] == 254);
        }

        return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || (bytes.Length == 16 && (bytes[0] & 0xFE) == 0xFC);
    }

    private void RefreshDnsCache()
    {
        if (Interlocked.Exchange(ref _isRefreshingDns, 1) == 1) return;
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -NonInteractive -Command \"Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Data -match '^[0-9]+\\.' } | Select-Object -First 250 | ForEach-Object { Write-Output ($_.Data + '|' + $_.Entry) }\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };

            Process? proc = null;
            InternalHelperProcessRegistry.BeginSpawnScope();
            try
            {
                proc = Process.Start(psi);
                if (proc is not null) InternalHelperProcessRegistry.Register(proc.Id);
            }
            finally
            {
                InternalHelperProcessRegistry.EndSpawnScope();
            }

            if (proc is null) return;
            using (proc)
            try
            {
                var readTask = proc.StandardOutput.ReadToEndAsync();
                if (!readTask.Wait(4500))
                {
                    try { proc.Kill(entireProcessTree: true); } catch { }
                    return;
                }
                var output = readTask.Result;

                foreach (var line in output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var idx = line.IndexOf('|');
                    if (idx > 0 && idx < line.Length - 1)
                    {
                        var ip = line[..idx].Trim();
                        var domain = line[(idx + 1)..].Trim();
                        if (!string.IsNullOrWhiteSpace(ip) && !string.IsNullOrWhiteSpace(domain))
                        {
                            _ipToDomainCache[ip] = domain;
                        }
                    }
                }
            }
            finally
            {
                InternalHelperProcessRegistry.Unregister(proc.Id);
            }
        }
        catch
        {
            // Ignore DNS cache errors.
        }
        finally
        {
            Interlocked.Exchange(ref _isRefreshingDns, 0);
        }
    }

    private void PollTcpTable()
    {
        if (Interlocked.Exchange(ref _isPolling, 1) == 1)
        {
            return;
        }

        try
        {
            var policy = _policyProvider();
            if (!policy.EnableNetworkGuard)
            {
                return;
            }

            foreach (var (pid, remoteIp, remotePort) in EnumerateActiveTcpConnections())
            {
                if (pid <= 4 || pid == Environment.ProcessId || IsLocalOrPrivateIp(remoteIp))
                {
                    continue;
                }

                var procPath = _processController.GetExecutablePath(pid);
                var procName = !string.IsNullOrWhiteSpace(procPath)
                    ? Path.GetFileNameWithoutExtension(procPath)
                    : _processController.GetProcessNameSafe(pid);

                var alert = EvaluateOutboundConnection(pid, procName, procPath, remoteIp, remotePort, policy);
                if (alert is not null)
                {
                    ThreatDetected?.Invoke(alert);
                }
            }
        }
        catch { }
        finally
        {
            Interlocked.Exchange(ref _isPolling, 0);
        }
    }

    private static IReadOnlyList<(int Pid, IPAddress RemoteIp, int RemotePort)> EnumerateActiveTcpConnections()
    {
        var results = new List<(int, IPAddress, int)>();
        EnumerateIpv4TcpRows(results);
        EnumerateIpv6TcpRows(results);
        return results;
    }

    private static void EnumerateIpv4TcpRows(List<(int Pid, IPAddress RemoteIp, int RemotePort)> results)
    {
        int bufferSize = 0;
        _ = NativeMethods.GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, NativeMethods.AF_INET, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);
        if (bufferSize <= 0) return;

        int allocSize = bufferSize + 4096;
        int actualSize = allocSize;
        var buffer = Marshal.AllocHGlobal(allocSize);
        try
        {
            uint ret = NativeMethods.GetExtendedTcpTable(buffer, ref actualSize, true, NativeMethods.AF_INET, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret != 0 || allocSize < sizeof(int)) return;

            int rowCount = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = IntPtr.Add(buffer, sizeof(int));
            int rowSize = Marshal.SizeOf<NativeMethods.MIB_TCPROW_OWNER_PID>();

            for (int i = 0; i < rowCount && sizeof(int) + ((long)(i + 1) * rowSize) <= allocSize; i++)
            {
                var row = Marshal.PtrToStructure<NativeMethods.MIB_TCPROW_OWNER_PID>(rowPtr);
                rowPtr = IntPtr.Add(rowPtr, rowSize);

                if (row.state is NativeMethods.MIB_TCP_STATE_ESTAB or NativeMethods.MIB_TCP_STATE_SYN_SENT)
                {
                    var remoteIp = new IPAddress(row.remoteAddr);
                    int remotePort = ((int)(row.remotePort & 0xFF) << 8) | (int)((row.remotePort & 0xFF00) >> 8);
                    results.Add((row.owningPid, remoteIp, remotePort));
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static void EnumerateIpv6TcpRows(List<(int Pid, IPAddress RemoteIp, int RemotePort)> results)
    {
        int bufferSize = 0;
        _ = NativeMethods.GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, NativeMethods.AF_INET6, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);
        if (bufferSize <= 0) return;

        int allocSize = bufferSize + 4096;
        int actualSize = allocSize;
        var buffer = Marshal.AllocHGlobal(allocSize);
        try
        {
            uint ret = NativeMethods.GetExtendedTcpTable(buffer, ref actualSize, true, NativeMethods.AF_INET6, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret != 0 || allocSize < sizeof(int)) return;

            int rowCount = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = IntPtr.Add(buffer, sizeof(int));
            int rowSize = Marshal.SizeOf<NativeMethods.MIB_TCP6ROW_OWNER_PID>();

            for (int i = 0; i < rowCount && sizeof(int) + ((long)(i + 1) * rowSize) <= allocSize; i++)
            {
                var row = Marshal.PtrToStructure<NativeMethods.MIB_TCP6ROW_OWNER_PID>(rowPtr);
                rowPtr = IntPtr.Add(rowPtr, rowSize);

                if (row.state is NativeMethods.MIB_TCP_STATE_ESTAB or NativeMethods.MIB_TCP_STATE_SYN_SENT &&
                    row.remoteAddr is { Length: 16 })
                {
                    var remoteIp = new IPAddress(row.remoteAddr);
                    int remotePort = ((int)(row.remotePort & 0xFF) << 8) | (int)((row.remotePort & 0xFF00) >> 8);
                    results.Add((row.owningPid, remoteIp, remotePort));
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public void Dispose()
    {
        Stop();
    }
}
