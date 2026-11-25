using System.Collections.Concurrent;
using System.Text;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using AegisSentinel.Core.Models;
using AegisSentinel.Core.Services;

namespace AegisSentinel.Core.Engine;

public sealed class EtwKernelTelemetryService : IDisposable
{
    private const string SessionName = "AegisSentinelKernelTelemetry";

    private readonly ProcessController _processController;
    private readonly SignatureVerifier _signatureVerifier;
    private readonly ProcessTreeTracker _treeTracker;
    private readonly ProcessRuleEvaluator _processEvaluator;
    private readonly RansomwareDetector _ransomwareDetector;
    private readonly CanaryManager _canaryManager;
    private readonly CredentialAndDllGuard _credentialGuard;
    private readonly NetworkGuardMonitor _networkGuard;
    private readonly BehaviorRiskEngine _riskEngine;
    private readonly Func<GuardPolicy> _policyProvider;
    private readonly TelemetryMetrics? _metrics;

    private static readonly string CachedWindowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";
    private readonly ConcurrentDictionary<int, (string Name, string Path)> _pidCache = new();
    private readonly ConcurrentDictionary<ulong, string> _fileObjectToPath = new();
    private readonly ConcurrentDictionary<ulong, string> _fileKeyToPath = new();
    private TraceEventSession? _session;
    private Thread? _listenerThread;
    private Timer? _flushTimer;
    private int _flushTick;
    private volatile bool _running;

    public bool IsRunning => _running;
    public event Action<SecurityEvent>? ThreatDetected;
    public event Action<string>? TelemetryError;

    public EtwKernelTelemetryService(
        ProcessController processController,
        SignatureVerifier signatureVerifier,
        ProcessTreeTracker treeTracker,
        ProcessRuleEvaluator processEvaluator,
        RansomwareDetector ransomwareDetector,
        CanaryManager canaryManager,
        CredentialAndDllGuard credentialGuard,
        NetworkGuardMonitor networkGuard,
        BehaviorRiskEngine riskEngine,
        Func<GuardPolicy> policyProvider,
        TelemetryMetrics? metrics = null)
    {
        _processController = processController;
        _signatureVerifier = signatureVerifier;
        _treeTracker = treeTracker;
        _processEvaluator = processEvaluator;
        _ransomwareDetector = ransomwareDetector;
        _canaryManager = canaryManager;
        _credentialGuard = credentialGuard;
        _networkGuard = networkGuard;
        _riskEngine = riskEngine;
        _policyProvider = policyProvider;
        _metrics = metrics;
    }

    public bool Start()
    {
        if (!ProcessController.IsCurrentProcessElevated())
        {
            return false;
        }

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
                BufferSizeMB = 8
            };
            _session = session;

            session.Source.Kernel.ProcessStart += OnProcessStart;
            session.Source.Kernel.ProcessStop += OnProcessStop;
            session.Source.Kernel.ImageLoad += OnImageLoad;
            session.Source.Kernel.FileIOName += OnFileIoName;
            session.Source.Kernel.FileIOFileCreate += OnFileIoName;
            session.Source.Kernel.FileIOCreate += OnFileIoCreate;
            session.Source.Kernel.FileIOWrite += OnFileIoWrite;
            session.Source.Kernel.FileIORename += OnFileIoRenameOrDelete;
            session.Source.Kernel.FileIODelete += OnFileIoRenameOrDelete;
            session.Source.Kernel.FileIOClose += OnFileIoClose;
            session.Source.Kernel.FileIOCleanup += OnFileIoClose;
            session.Source.Kernel.TcpIpConnect += OnTcpIpConnect;
            session.Source.Kernel.TcpIpConnectIPV6 += OnTcpIpConnectV6;
            session.Source.Kernel.RegistrySetValue += OnRegistrySetValue;

            session.EnableKernelProvider(
                KernelTraceEventParser.Keywords.Process |
                KernelTraceEventParser.Keywords.ImageLoad |
                KernelTraceEventParser.Keywords.FileIOInit |
                KernelTraceEventParser.Keywords.FileIO |
                KernelTraceEventParser.Keywords.NetworkTCPIP |
                KernelTraceEventParser.Keywords.Registry);

            _running = true;

            // Battery-aware ETW flush ticker: 1.2s on AC power, 2.4s on laptop battery to preserve CPU C-states
            _flushTimer = new Timer(_ =>
            {
                int tick = Interlocked.Increment(ref _flushTick);
                if (PowerProfileHelper.IsOnBatteryPower && (tick & 1) == 1)
                {
                    return; // Skip alternate flush ticks on battery (2.4s effective cadence)
                }
                try { session.Flush(); } catch { }
            }, null, TimeSpan.FromMilliseconds(1200), TimeSpan.FromMilliseconds(1200));

            _listenerThread = new Thread(() =>
            {
                try
                {
                    session.Source.Process();
                }
                catch (Exception ex) when (_running && ReferenceEquals(_session, session))
                {
                    TelemetryError?.Invoke($"ETW 세션 중단: {ex.Message}");
                }
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
                Name = "AegisSentinel-ETW-Kernel"
            };
            _listenerThread.Start();
            return true;
        }
        catch (Exception ex)
        {
            TelemetryError?.Invoke($"ETW 시작 실패: {ex.Message}");
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

    private void OnProcessStart(ProcessTraceData data)
    {
        _metrics?.IncrementProcessEvent();
        if (data.ProcessID <= 4 ||
            data.ProcessID == Environment.ProcessId ||
            InternalHelperProcessRegistry.IsInternalHelper(data.ProcessID, data.ParentID)) return;

        try
        {
            var policy = _policyProvider();
            var procPath = _processController.GetExecutablePath(data.ProcessID);
            if (string.IsNullOrWhiteSpace(procPath) && !string.IsNullOrWhiteSpace(data.ImageFileName))
            {
                var normalizedImg = NormalizeNtDevicePath(data.ImageFileName);
                if (Path.IsPathRooted(normalizedImg))
                {
                    procPath = normalizedImg;
                }
            }

            var procName = string.IsNullOrWhiteSpace(data.ProcessName)
                ? Path.GetFileNameWithoutExtension(procPath)
                : data.ProcessName;

            if (_pidCache.Count > 8192) _pidCache.Clear();
            _pidCache[data.ProcessID] = (procName, procPath);
            _treeTracker.RecordStart(data.ProcessID, data.ParentID, procName, procPath, data.CommandLine ?? string.Empty);

            var (parentName, parentPath) = ResolveProcessInfo(data.ParentID);
            var sig = File.Exists(procPath)
                ? _signatureVerifier.VerifyFile(procPath)
                : new SignatureInfo(SignatureStatus.Unknown, string.Empty);

            var ctx = new ProcessEvaluationContext
            {
                ProcessId = data.ProcessID,
                ProcessName = procName,
                ProcessPath = procPath,
                CommandLine = data.CommandLine ?? string.Empty,
                ParentProcessId = data.ParentID,
                ParentProcessName = parentName,
                ParentProcessPath = parentPath,
                AncestryChain = _treeTracker.FormatAncestryString(data.ProcessID),
                Signature = sig
            };

            var alert = _processEvaluator.Evaluate(ctx, policy);
            if (alert is not null)
            {
                ThreatDetected?.Invoke(alert);
            }
        }
        catch { }
    }

    private void OnProcessStop(ProcessTraceData data)
    {
        _pidCache.TryRemove(data.ProcessID, out _);
        _treeTracker.RecordStop(data.ProcessID);
        _riskEngine.ClearProcess(data.ProcessID);
        _ransomwareDetector.ClearProcess(data.ProcessID);
    }

    private void OnImageLoad(ImageLoadTraceData data)
    {
        if (data.ProcessID <= 4 ||
            data.ProcessID == Environment.ProcessId ||
            InternalHelperProcessRegistry.IsInternalHelper(data.ProcessID)) return;

        var rawFile = data.FileName;
        if (string.IsNullOrWhiteSpace(rawFile) ||
            !rawFile.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var dllPath = NormalizeNtDevicePath(rawFile);
        if (CachedWindowsDir.Length > 1 &&
            dllPath.StartsWith(CachedWindowsDir, StringComparison.OrdinalIgnoreCase) &&
            !dllPath.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) &&
            !dllPath.Contains(@"\Tasks\", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        try
        {
            var policy = _policyProvider();
            var (procName, procPath) = ResolveProcessInfo(data.ProcessID);
            var alert = _credentialGuard.EvaluateDllDropOrLoad(data.ProcessID, procName, procPath, dllPath, policy);
            if (alert is not null)
            {
                ThreatDetected?.Invoke(alert);
            }
        }
        catch { }
    }

    private void OnRegistrySetValue(RegistryTraceData data)
    {
        _metrics?.IncrementRegistryEvent();
        int pid = data.ProcessID;
        if (pid <= 4 || pid == Environment.ProcessId || InternalHelperProcessRegistry.IsInternalHelper(pid)) return;

        var keyName = data.KeyName;
        if (string.IsNullOrWhiteSpace(keyName)) return;

        // Ultra-fast hot-path filter: skip 98% of routine OS registry writes before evaluating rules
        if (!keyName.Contains(@"\CurrentVersion\", StringComparison.OrdinalIgnoreCase) &&
            !keyName.Contains(@"\Classes\", StringComparison.OrdinalIgnoreCase) &&
            !keyName.Contains(@"\Windows Defender\", StringComparison.OrdinalIgnoreCase) &&
            !keyName.Contains(@"\Image File Execution Options\", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        try
        {
            var policy = _policyProvider();
            var alert = EvaluateRealtimeRegistryWrite(pid, keyName, data.ValueName ?? string.Empty, policy);
            if (alert is not null)
            {
                ThreatDetected?.Invoke(alert);
            }
        }
        catch { }
    }

    public SecurityEvent? EvaluateRealtimeRegistryWrite(int pid, string keyName, string valueName, GuardPolicy policy)
    {
        if (!policy.EnablePersistenceGuard && !policy.EnableSystemIntegrityGuard) return null;

        bool isUacHijack = keyName.Contains(@"\Classes\ms-settings\Shell\Open\command", StringComparison.OrdinalIgnoreCase) ||
                           keyName.Contains(@"\Classes\ms-settings\CurVer", StringComparison.OrdinalIgnoreCase) ||
                           keyName.Contains(@"\Classes\mscfile\Shell\Open\command", StringComparison.OrdinalIgnoreCase);

        bool isDefenderExcl = policy.EnableSystemIntegrityGuard &&
                              keyName.Contains(@"\Windows Defender\Exclusions", StringComparison.OrdinalIgnoreCase);
        bool isIfeoDebugger = policy.EnablePersistenceGuard &&
                              keyName.Contains(@"\Image File Execution Options\", StringComparison.OrdinalIgnoreCase) &&
                              valueName.Equals("Debugger", StringComparison.OrdinalIgnoreCase);
        bool isWinlogonHijack = policy.EnablePersistenceGuard &&
                                keyName.Contains(@"\Windows NT\CurrentVersion\Winlogon", StringComparison.OrdinalIgnoreCase) &&
                                (valueName.Equals("Shell", StringComparison.OrdinalIgnoreCase) ||
                                 valueName.Equals("Userinit", StringComparison.OrdinalIgnoreCase));
        bool isProxyHijack = policy.EnableSystemIntegrityGuard &&
                             keyName.Contains(@"\CurrentVersion\Internet Settings", StringComparison.OrdinalIgnoreCase) &&
                             (valueName.Equals("ProxyServer", StringComparison.OrdinalIgnoreCase) ||
                              valueName.Equals("AutoConfigURL", StringComparison.OrdinalIgnoreCase));
        bool isRunKey = policy.EnablePersistenceGuard &&
                        (keyName.EndsWith(@"\CurrentVersion\Run", StringComparison.OrdinalIgnoreCase) ||
                         keyName.EndsWith(@"\CurrentVersion\RunOnce", StringComparison.OrdinalIgnoreCase));

        if (!isUacHijack && !isDefenderExcl && !isIfeoDebugger && !isWinlogonHijack && !isProxyHijack && !isRunKey)
        {
            return null;
        }

        var (procName, procPath) = ResolveProcessInfo(pid);
        if (ProcessRuleEvaluator.IsProtectedHostIdeProcess(procPath))
        {
            return null;
        }

        if (!string.IsNullOrWhiteSpace(procPath) &&
            policy.WhitelistedExecutablePaths.Contains(procPath, StringComparer.OrdinalIgnoreCase))
        {
            return null;
        }

        var sig = File.Exists(procPath)
            ? _signatureVerifier.VerifyFile(procPath)
            : new SignatureInfo(SignatureStatus.Unknown, string.Empty);

        // Ignore signed vendor/Microsoft processes writing normal Run or Proxy settings
        if ((isRunKey || isProxyHijack) && sig.IsSigned)
        {
            return null;
        }

        if (isUacHijack)
        {
            // Immediately rollback the flash UAC hijack key before fodhelper/eventvwr reads it!
            SystemIntegrityGuard.CheckAndCleanUacBypassRegistryKeys();
            return new SecurityEvent
            {
                Severity = ThreatSeverity.Critical,
                Category = ThreatCategory.PrivilegeEscalation,
                ActionTaken = SecurityActionTaken.RolledBack,
                Title = "실시간 ETW: UAC 권한 상승 우회 레지스트리 쓰기 즉시 차단!",
                Description = $"'{procName}' (PID {pid})가 UAC 우회 키({keyName})를 변조하려 해 즉시 롤백하고 프로세스를 포착했습니다.",
                ProcessId = pid,
                ProcessName = procName,
                ProcessPath = procPath,
                TargetPath = $"{keyName}\\{valueName}",
                RiskScore = 100,
                RiskSignals = new List<string> { "EtwRealtimeUacHijack(+100)" },
                Signature = sig
            };
        }

        if (isDefenderExcl || isIfeoDebugger || isWinlogonHijack)
        {
            // Exempt verified TrustedMicrosoft OS/Defender services (e.g. MsMpEng, TiWorker, TrustedInstaller, Group Policy svchost)
            if (sig.Status == SignatureStatus.TrustedMicrosoft &&
                !string.IsNullOrWhiteSpace(procPath) &&
                QuarantineManager.IsProtectedSystemOrSelfPath(procPath))
            {
                var exe = Path.GetFileName(procPath);
                if (exe.Equals("MsMpEng.exe", StringComparison.OrdinalIgnoreCase) ||
                    exe.Equals("MpDefenderCoreService.exe", StringComparison.OrdinalIgnoreCase) ||
                    exe.Equals("TiWorker.exe", StringComparison.OrdinalIgnoreCase) ||
                    exe.Equals("TrustedInstaller.exe", StringComparison.OrdinalIgnoreCase) ||
                    exe.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase))
                {
                    return null;
                }
            }

            return new SecurityEvent
            {
                Severity = ThreatSeverity.Critical,
                Category = isDefenderExcl ? ThreatCategory.SystemIntegrityTamper : ThreatCategory.Persistence,
                ActionTaken = SecurityActionTaken.Logged,
                Title = isDefenderExcl
                    ? "실시간 ETW: Windows Defender 검사 예외 무단 등록 탐지!"
                    : "실시간 ETW: 시스템 핵심 지속성(IFEO/Winlogon) 하이재킹 탐지!",
                Description = $"'{procName}' (PID {pid})가 보호 레지스트리({keyName}\\{valueName})에 쓰기를 시도했습니다.",
                ProcessId = pid,
                ProcessName = procName,
                ProcessPath = procPath,
                TargetPath = $"{keyName}\\{valueName}",
                RiskScore = 95,
                RiskSignals = new List<string> { "EtwCriticalRegistryTamper(+95)" },
                Signature = sig
            };
        }

        const int unsignedRunOrProxyScore = 75;
        return new SecurityEvent
        {
            Severity = ThreatSeverity.High,
            Category = isProxyHijack ? ThreatCategory.SystemIntegrityTamper : ThreatCategory.Persistence,
            ActionTaken = SecurityActionTaken.Logged,
            Title = isProxyHijack
                ? "실시간 ETW: 비신뢰 프로세스의 프록시 설정 변경 탐지"
                : "실시간 ETW: 자동 실행(Run/RunOnce) 레지스트리 등록 탐지",
            Description = $"'{procName}' (PID {pid})가 '{keyName}\\{valueName}' 값을 기록했습니다.",
            ProcessId = pid,
            ProcessName = procName,
            ProcessPath = procPath,
            TargetPath = $"{keyName}\\{valueName}",
            RiskScore = unsignedRunOrProxyScore,
            RiskSignals = new List<string> { $"EtwRegistryWrite:{(isProxyHijack ? "Proxy" : "Run")}(+{unsignedRunOrProxyScore})" },
            Signature = sig
        };
    }

    private void OnTcpIpConnect(TcpIpConnectTraceData data)
    {
        _metrics?.IncrementNetworkEvent();
        if (data.ProcessID <= 4 ||
            data.ProcessID == Environment.ProcessId ||
            InternalHelperProcessRegistry.IsInternalHelper(data.ProcessID)) return;

        try
        {
            var policy = _policyProvider();
            var (procName, procPath) = ResolveProcessInfo(data.ProcessID);
            var alert = _networkGuard.EvaluateOutboundConnection(
                data.ProcessID, procName, procPath, data.daddr, data.dport, policy);
            if (alert is not null)
            {
                ThreatDetected?.Invoke(alert);
            }
        }
        catch { }
    }

    private void OnTcpIpConnectV6(TcpIpV6ConnectTraceData data)
    {
        _metrics?.IncrementNetworkEvent();
        if (data.ProcessID <= 4 ||
            data.ProcessID == Environment.ProcessId ||
            InternalHelperProcessRegistry.IsInternalHelper(data.ProcessID)) return;

        try
        {
            var policy = _policyProvider();
            var (procName, procPath) = ResolveProcessInfo(data.ProcessID);
            var alert = _networkGuard.EvaluateOutboundConnection(
                data.ProcessID, procName, procPath, data.daddr, data.dport, policy);
            if (alert is not null)
            {
                ThreatDetected?.Invoke(alert);
            }
        }
        catch { }
    }

    private static bool IsVolumeRootNtfsMetadata(string path)
    {
        return path.Contains(@":\$Mft", StringComparison.OrdinalIgnoreCase) ||
               path.Contains(@":\$LogFile", StringComparison.OrdinalIgnoreCase) ||
               path.Contains(@":\$Extend\", StringComparison.OrdinalIgnoreCase) ||
               path.Contains(@":\$BitMap", StringComparison.OrdinalIgnoreCase) ||
               path.Contains(@":\$Recycle.Bin\", StringComparison.OrdinalIgnoreCase) ||
               path.Contains(@"Volume", StringComparison.OrdinalIgnoreCase) && path.Contains(@"\$Mft", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsTrackableUserFilePath(string rawPath)
    {
        // Only cache FileObject -> Path mappings for user-relevant files, skipping 95%+ of OS/Program Files/NTFS metadata noise
        // (Note: allow C:\Windows\Temp and C:\Windows\Tasks!)
        if ((rawPath.Contains(@"\Windows\", StringComparison.OrdinalIgnoreCase) &&
             !rawPath.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) &&
             !rawPath.Contains(@"\Tasks\", StringComparison.OrdinalIgnoreCase)) ||
            rawPath.Contains(@"\Program Files", StringComparison.OrdinalIgnoreCase) ||
            rawPath.Contains(@"\ProgramData\Microsoft\", StringComparison.OrdinalIgnoreCase) ||
            IsVolumeRootNtfsMetadata(rawPath))
        {
            return false;
        }
        return true;
    }

    private void OnFileIoClose(FileIOSimpleOpTraceData data)
    {
        if (data.FileObject != 0)
        {
            _fileObjectToPath.TryRemove(data.FileObject, out _);
        }
    }

    private void OnFileIoName(FileIONameTraceData data)
    {
        if (data.FileKey == 0) return;
        if (!string.IsNullOrWhiteSpace(data.FileName) && IsTrackableUserFilePath(data.FileName))
        {
            if (_fileKeyToPath.Count > 8192) _fileKeyToPath.Clear();
            _fileKeyToPath[data.FileKey] = data.FileName;
        }
        else
        {
            _fileKeyToPath.TryRemove(data.FileKey, out _);
        }
    }

    private void OnFileIoCreate(FileIOCreateTraceData data)
    {
        if (data.FileObject != 0)
        {
            if (!string.IsNullOrWhiteSpace(data.FileName) && IsTrackableUserFilePath(data.FileName))
            {
                if (_fileObjectToPath.Count > 8192) _fileObjectToPath.Clear();
                _fileObjectToPath[data.FileObject] = data.FileName;
            }
            else
            {
                // CRITICAL: Evict stale path when kernel recycles a freed FILE_OBJECT pointer for an untracked OS file!
                _fileObjectToPath.TryRemove(data.FileObject, out _);
            }
        }
        HandleFileIo(data.ProcessID, data.FileName, isWriteOrModify: false, isRenameOrDelete: false);
    }

    private void OnFileIoWrite(FileIOReadWriteTraceData data)
    {
        var fileName = !string.IsNullOrWhiteSpace(data.FileName)
            ? data.FileName
            : (data.FileObject != 0 && _fileObjectToPath.TryGetValue(data.FileObject, out var byObj)
                ? byObj
                : (data.FileKey != 0 && _fileKeyToPath.TryGetValue(data.FileKey, out var byKey) ? byKey : string.Empty));
        HandleFileIo(data.ProcessID, fileName, isWriteOrModify: true, isRenameOrDelete: false);
    }

    private void OnFileIoRenameOrDelete(FileIOInfoTraceData data)
    {
        var fileName = !string.IsNullOrWhiteSpace(data.FileName)
            ? data.FileName
            : (data.FileObject != 0 && _fileObjectToPath.TryGetValue(data.FileObject, out var byObj)
                ? byObj
                : (data.FileKey != 0 && _fileKeyToPath.TryGetValue(data.FileKey, out var byKey) ? byKey : string.Empty));
        HandleFileIo(data.ProcessID, fileName, isWriteOrModify: true, isRenameOrDelete: true);
    }

    private void HandleFileIo(int pid, string? rawFilePath, bool isWriteOrModify, bool isRenameOrDelete)
    {
        _metrics?.IncrementFileEvent();
        if (pid <= 4 ||
            pid == Environment.ProcessId ||
            InternalHelperProcessRegistry.IsInternalHelper(pid) ||
            string.IsNullOrWhiteSpace(rawFilePath))
        {
            return;
        }

        var filePath = NormalizeNtDevicePath(rawFilePath);

        // Hot-path fast reject: Windows system files, Program Files, and NTFS metadata streams ($Mft, $LogFile)
        // are neither user protected folders nor user credential paths.
        if (IsVolumeRootNtfsMetadata(filePath) ||
            (CachedWindowsDir.Length > 1 && filePath.StartsWith(CachedWindowsDir, StringComparison.OrdinalIgnoreCase)) ||
            filePath.StartsWith(@"C:\Program Files\", StringComparison.OrdinalIgnoreCase) ||
            filePath.StartsWith(@"C:\Program Files (x86)\", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var policy = _policyProvider();

        // Only evaluate Ransomware on actual Writes / Renames / Deletes — NEVER on read-only FileIOCreate!
        bool isProtectedWrite = isWriteOrModify &&
                                (IsInsideProtectedFolders(filePath, policy) || _canaryManager.IsCanaryPath(filePath));
        bool looksSensitive = filePath.Contains(@"\User Data\", StringComparison.OrdinalIgnoreCase) ||
                              filePath.Contains(@"\Opera Software\", StringComparison.OrdinalIgnoreCase) ||
                              filePath.Contains(@"\Mozilla\Firefox\Profiles\", StringComparison.OrdinalIgnoreCase) ||
                              filePath.Contains(@"\.ssh\", StringComparison.OrdinalIgnoreCase) ||
                              filePath.Contains(@"\.aws\", StringComparison.OrdinalIgnoreCase) ||
                              filePath.Contains(@"\.kube\", StringComparison.OrdinalIgnoreCase) ||
                              filePath.Contains(@"\.azure\", StringComparison.OrdinalIgnoreCase) ||
                              filePath.Contains(@"\Solana\", StringComparison.OrdinalIgnoreCase) ||
                              filePath.Contains(@"\Exodus\", StringComparison.OrdinalIgnoreCase) ||
                              filePath.Contains(@"\Electrum\", StringComparison.OrdinalIgnoreCase) ||
                              filePath.Contains(@"\MetaMask\", StringComparison.OrdinalIgnoreCase) ||
                              filePath.Contains(@"\nkbihfbeogaeaoehlefnkodbefgpgknn\", StringComparison.OrdinalIgnoreCase) ||
                              filePath.Contains(@"\bfnaelmomeimhlpmgjnjophhpkkoljpa\", StringComparison.OrdinalIgnoreCase);

        if (!isProtectedWrite && !looksSensitive) return;

        var (procName, procPath) = ResolveProcessInfo(pid);
        if (ProcessRuleEvaluator.IsProtectedHostIdeProcess(procPath))
        {
            return;
        }

        if (looksSensitive)
        {
            var credAlert = _credentialGuard.EvaluateSensitiveFileAccess(pid, procName, procPath, filePath, policy);
            if (credAlert is not null)
            {
                ThreatDetected?.Invoke(credAlert);
            }
        }

        if (isProtectedWrite)
        {
            var isCanary = _canaryManager.IsCanaryPath(filePath);
            var ransomAlert = _ransomwareDetector.RecordFileActivity(
                pid, procName, procPath, filePath, isRenameOrDelete, isCanary, policy);
            if (ransomAlert is not null)
            {
                ThreatDetected?.Invoke(ransomAlert);
            }
        }
    }

    private (string Name, string Path) ResolveProcessInfo(int pid)
    {
        if (pid <= 4) return ("System", string.Empty);

        if (_pidCache.TryGetValue(pid, out var cached) && !string.IsNullOrWhiteSpace(cached.Path))
        {
            return cached;
        }

        var path = _processController.GetExecutablePath(pid);
        var name = !string.IsNullOrWhiteSpace(path)
            ? Path.GetFileNameWithoutExtension(path)
            : _processController.GetProcessNameSafe(pid);

        var entry = (name, path);
        if (!string.IsNullOrWhiteSpace(name))
        {
            _pidCache[pid] = entry;
        }
        return entry;
    }

    private static volatile Dictionary<string, string> _ntDeviceToDriveMap = BuildDeviceMap();
    private static long _lastDeviceMapRefreshTicks;

    public static string NormalizeNtDevicePath(string path)
    {
        if (path.StartsWith(@"\??\UNC\", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            return @"\\" + path[8..];
        }
        if (path.StartsWith(@"\??\", StringComparison.Ordinal) || path.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            path = path[4..];
        }

        if (!path.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
        {
            return path;
        }

        var map = _ntDeviceToDriveMap;
        foreach (var kvp in map)
        {
            // Enforce exact volume boundary (\Device\HarddiskVolume1\ must NEVER match \Device\HarddiskVolume10\!)
            if (path.StartsWith(kvp.Key + "\\", StringComparison.OrdinalIgnoreCase) ||
                path.Equals(kvp.Key, StringComparison.OrdinalIgnoreCase))
            {
                return kvp.Value + path[kvp.Key.Length..];
            }
        }

        // Refresh device map (throttled to once every 10s) when a newly mounted USB/ISO volume appears
        var nowTicks = Environment.TickCount64;
        var lastTicks = Interlocked.Read(ref _lastDeviceMapRefreshTicks);
        if (nowTicks - lastTicks >= 10_000 &&
            Interlocked.CompareExchange(ref _lastDeviceMapRefreshTicks, nowTicks, lastTicks) == lastTicks)
        {
            var refreshed = BuildDeviceMap();
            _ntDeviceToDriveMap = refreshed;
            foreach (var kvp in refreshed)
            {
                if (path.StartsWith(kvp.Key + "\\", StringComparison.OrdinalIgnoreCase) ||
                    path.Equals(kvp.Key, StringComparison.OrdinalIgnoreCase))
                {
                    return kvp.Value + path[kvp.Key.Length..];
                }
            }
        }

        return path;
    }

    private static Dictionary<string, string> BuildDeviceMap()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var sb = new StringBuilder(260);
        for (char c = 'A'; c <= 'Z'; c++)
        {
            sb.Clear();
            var drive = $"{c}:";
            uint len = Native.NativeMethods.QueryDosDevice(drive, sb, (uint)sb.Capacity);
            if (len > 0)
            {
                var target = sb.ToString().TrimEnd('\0');
                if (!string.IsNullOrWhiteSpace(target))
                {
                    map[target] = drive;
                }
            }
        }
        return map;
    }

    private static bool IsInsideProtectedFolders(string filePath, GuardPolicy policy)
    {
        foreach (var folder in policy.ProtectedFolders)
        {
            if (string.IsNullOrWhiteSpace(folder)) continue;
            var prefix = folder.EndsWith('\\') ? folder : folder + "\\";
            if (filePath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    public void Dispose()
    {
        Stop();
    }
}
