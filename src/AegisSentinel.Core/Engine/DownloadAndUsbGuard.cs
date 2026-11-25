using System.Collections.Concurrent;
using AegisSentinel.Core.Models;

namespace AegisSentinel.Core.Engine;

/// <summary>
/// Watches the user's Downloads folder (Mark-of-the-Web + PE static heuristic scan on new downloads)
/// and newly mounted USB / removable drives for autorun/dropper threats.
/// </summary>
public sealed class DownloadAndUsbGuard : IDisposable
{
    private static readonly HashSet<string> RealtimeDownloadScanExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".com", ".sys", ".msi", ".cpl", ".xll", ".ps1", ".bat", ".cmd",
        ".vbs", ".js", ".wsf", ".sct", ".hta", ".lnk", ".iso", ".vhd", ".vhdx", ".img", ".chm", ".zip", ".docm", ".xlsm"
    };

    private readonly ThreatScanner _scanner;
    private readonly Func<GuardPolicy> _policyProvider;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _recentScans = new(StringComparer.OrdinalIgnoreCase);
    private FileSystemWatcher? _downloadsWatcher;
    private Timer? _usbPollTimer;
    private CancellationTokenSource? _stopCts;
    private int _pollTick;
    private int _isCheckingDrives;
    private readonly object _driveSync = new();
    private HashSet<string> _knownRemovableDrives = new(StringComparer.OrdinalIgnoreCase);

    public event Action<SecurityEvent>? ThreatDetected;

    public DownloadAndUsbGuard(ThreatScanner scanner, Func<GuardPolicy> policyProvider)
    {
        _scanner = scanner;
        _policyProvider = policyProvider;
    }

    public void Start()
    {
        Stop();
        _stopCts = new CancellationTokenSource();

        var downloadsDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "Downloads");

        if (Directory.Exists(downloadsDir))
        {
            try
            {
                _downloadsWatcher = new FileSystemWatcher(downloadsDir)
                {
                    IncludeSubdirectories = false,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime | NotifyFilters.LastWrite,
                    EnableRaisingEvents = true
                };

                _downloadsWatcher.Created += (_, e) => ScheduleDownloadScan(e.FullPath);
                _downloadsWatcher.Renamed += (_, e) => ScheduleDownloadScan(e.FullPath);
            }
            catch
            {
                // Ignore if Downloads cannot be watched.
            }
        }

        lock (_driveSync)
        {
            _knownRemovableDrives = GetCurrentRemovableRoots();
        }
        // Low-power 30s backup timer (60s on battery); real-time detection happens instantaneously via WM_DEVICECHANGE!
        _usbPollTimer = new Timer(_ =>
        {
            int tick = Interlocked.Increment(ref _pollTick);
            if (Services.PowerProfileHelper.IsOnBatteryPower && (tick & 1) == 1) return;
            PollRemovableDrives();
        }, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
    }

    /// <summary>
    /// Called immediately on Windows WM_DEVICECHANGE (DBT_DEVICEARRIVAL) so newly plugged USB drives
    /// are scanned instantaneously with zero high-frequency polling.
    /// </summary>
    public void NotifyDeviceArrival()
    {
        _ = Task.Run(async () =>
        {
            PollRemovableDrives();
            // Retry once after 1.5s in case the USB volume was still mounting (!IsReady) at the exact instant WM_DEVICECHANGE fired
            var cts = _stopCts;
            if (cts is not null && !cts.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(1500, cts.Token);
                    PollRemovableDrives();
                }
                catch { }
            }
        });
    }

    public void Stop()
    {
        if (_downloadsWatcher is not null)
        {
            _downloadsWatcher.EnableRaisingEvents = false;
            _downloadsWatcher.Dispose();
            _downloadsWatcher = null;
        }

        _usbPollTimer?.Dispose();
        _usbPollTimer = null;

        var cts = Interlocked.Exchange(ref _stopCts, null);
        if (cts is not null)
        {
            try { cts.Cancel(); } catch { }
            cts.Dispose();
        }

        _recentScans.Clear();
    }

    public IReadOnlyList<SecurityEvent> ScanRemovableDriveRoot(string rootPath, GuardPolicy policy)
    {
        var alerts = new List<SecurityEvent>();
        if (!policy.EnableDownloadAndUsbGuard || string.IsNullOrWhiteSpace(rootPath) || !Directory.Exists(rootPath))
        {
            return alerts;
        }

        var autorunPath = Path.Combine(rootPath, "autorun.inf");
        if (File.Exists(autorunPath))
        {
            alerts.Add(new SecurityEvent
            {
                Severity = ThreatSeverity.High,
                Category = ThreatCategory.UsbOrDownloadThreat,
                ActionTaken = SecurityActionTaken.Logged,
                Title = "USB 이동식 드라이브에서 의심스러운 autorun.inf 발견",
                Description = $"새로 연결된 이동식 드라이브({rootPath}) 루트에 자동 실행 설정 파일(autorun.inf)이 존재합니다.",
                TargetPath = autorunPath,
                RiskScore = 75,
                RiskSignals = new List<string> { "UsbAutorunInf(+75)" }
            });
        }

        try
        {
            foreach (var file in Directory.EnumerateFiles(rootPath).Take(100))
            {
                var finding = _scanner.ScanFile(file, policy, includeClean: false);
                if (finding is not null && finding.RiskScore >= 60)
                {
                    alerts.Add(new SecurityEvent
                    {
                        Severity = finding.Severity,
                        Category = ThreatCategory.UsbOrDownloadThreat,
                        ActionTaken = SecurityActionTaken.Logged,
                        Title = $"USB 드라이브 위험 실행 파일 탐지: {Path.GetFileName(file)}",
                        Description = string.Join(" | ", finding.Reasons),
                        TargetPath = file,
                        RiskScore = finding.RiskScore,
                        RiskSignals = finding.Reasons.ToList(),
                        Signature = finding.Signature
                    });
                }
            }
        }
        catch
        {
            // Ignore unreadable USB folders.
        }

        return alerts;
    }

    private void ScheduleDownloadScan(string filePath)
    {
        var ext = Path.GetExtension(filePath);
        if (string.IsNullOrWhiteSpace(ext) || !RealtimeDownloadScanExtensions.Contains(ext))
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        if (_recentScans.TryGetValue(filePath, out var lastScan) && (now - lastScan).TotalSeconds < 5)
        {
            return;
        }
        _recentScans[filePath] = now;
        if (_recentScans.Count > 512) _recentScans.Clear();

        CancellationToken ct;
        try
        {
            ct = _stopCts?.Token ?? CancellationToken.None;
        }
        catch (ObjectDisposedException)
        {
            return;
        }
        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(1200, ct); // Allow browser download flush
                // Wait briefly if a large download is still growing or exclusively write-locked
                long prevLen = -1;
                for (int attempt = 0; attempt < 3 && !ct.IsCancellationRequested && File.Exists(filePath); attempt++)
                {
                    try
                    {
                        var curLen = new FileInfo(filePath).Length;
                        using var probe = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
                        if (curLen == prevLen || attempt > 0) break;
                        prevLen = curLen;
                    }
                    catch (IOException)
                    {
                        await Task.Delay(800, ct);
                    }
                }
                var policy = _policyProvider();
                if (ct.IsCancellationRequested || !policy.EnableDownloadAndUsbGuard || !File.Exists(filePath))
                {
                    return;
                }

                var finding = _scanner.ScanFile(filePath, policy, includeClean: false);
                if (finding is not null && finding.RiskScore >= 55)
                {
                    ThreatDetected?.Invoke(new SecurityEvent
                    {
                        Severity = finding.Severity,
                        Category = ThreatCategory.UsbOrDownloadThreat,
                        ActionTaken = SecurityActionTaken.Logged,
                        Title = $"위험한 다운로드 파일 탐지: {Path.GetFileName(filePath)}",
                        Description = string.Join(" | ", finding.Reasons),
                        TargetPath = filePath,
                        RiskScore = finding.RiskScore,
                        RiskSignals = finding.Reasons.ToList(),
                        Signature = finding.Signature
                    });
                }
            }
            catch (OperationCanceledException) { }
            catch { }
        }, ct);
    }

    private void PollRemovableDrives()
    {
        if (Interlocked.Exchange(ref _isCheckingDrives, 1) == 1) return;
        try
        {
            var policy = _policyProvider();
            if (!policy.EnableDownloadAndUsbGuard)
            {
                return;
            }

            var current = GetCurrentRemovableRoots();
            var newlyAdded = new List<string>();
            lock (_driveSync)
            {
                foreach (var root in current)
                {
                    if (_knownRemovableDrives.Add(root))
                    {
                        newlyAdded.Add(root);
                    }
                }
                _knownRemovableDrives.IntersectWith(current);
            }

            foreach (var root in newlyAdded)
            {
                foreach (var alert in ScanRemovableDriveRoot(root, policy))
                {
                    ThreatDetected?.Invoke(alert);
                }
            }
        }
        catch
        {
            // Ignore drive enumeration failures.
        }
        finally
        {
            Interlocked.Exchange(ref _isCheckingDrives, 0);
        }
    }

    private static HashSet<string> GetCurrentRemovableRoots()
    {
        var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var drive in DriveInfo.GetDrives())
        {
            try
            {
                if (drive.DriveType == DriveType.Removable && drive.IsReady)
                {
                    roots.Add(drive.RootDirectory.FullName);
                }
            }
            catch { }
        }
        return roots;
    }

    public void Dispose()
    {
        Stop();
    }
}
