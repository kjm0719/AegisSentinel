using System.Collections.Concurrent;
using System.Diagnostics;
using AegisSentinel.Core.Models;
using AegisSentinel.Core.Services;

namespace AegisSentinel.Core.Engine;

public sealed class SecurityOrchestrator : IDisposable
{
    private readonly PolicyStore _policyStore;
    private readonly ProcessController _processController;
    private readonly SignatureVerifier _signatureVerifier;
    private readonly ThreatIntelStore _intelStore;
    private readonly QuarantineManager _quarantineManager;
    private readonly RecoveryVault _recoveryVault;
    private readonly AuditLogService _auditLog;
    private readonly ProcessTreeTracker _treeTracker;
    private readonly BehaviorRiskEngine _riskEngine;
    private readonly CustomRuleEngine _customRuleEngine;
    private readonly TelemetryMetrics _metrics;
    private readonly ThreatScanner _scanner;
    private readonly BrowserAndPupCleaner _browserPupCleaner;
    private readonly MzkDeepScanner _mzkScanner;
    private readonly MalwareRemediationService _remediationService;
    private readonly ProcessRuleEvaluator _processEvaluator;
    private readonly RansomwareDetector _ransomwareDetector;
    private readonly CanaryManager _canaryManager;
    private readonly PersistenceMonitor _persistenceMonitor;
    private readonly CredentialAndDllGuard _credentialGuard;
    private readonly NetworkGuardMonitor _networkGuard;
    private readonly FilelessScriptGuard _filelessScriptGuard;
    private readonly DownloadAndUsbGuard _downloadUsbGuard;
    private readonly SystemIntegrityGuard _systemIntegrityGuard;
    private readonly ClipboardGuard _clipboardGuard;
    private readonly EtwKernelTelemetryService _etwService;
    private readonly EtwDnsTelemetryService _etwDnsService;
    private readonly FallbackProcessAndFileMonitor _fallbackMonitor;

    private readonly Dictionary<string, (DateTimeOffset LastSeen, int LastRiskScore)> _dedupCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _dedupLock = new();
    private readonly ConcurrentDictionary<int, (string ProcessPath, DateTimeOffset AllowedAt)> _sessionAllowedPids = new();
    private readonly ConcurrentDictionary<int, byte> _activeInterventionPids = new();
    private readonly object _lifecycleLock = new();
    private volatile GuardPolicy _policy;
    private volatile bool _isRunning;
    private Timer? _vaultSyncTimer;
    private Timer? _memorySweepTimer;
    private Timer? _dailyDbSyncTimer;
    private int _vaultTick;
    private int _memorySweepTick;
    private int _isSyncingVault;
    private int _isSweepingMemory;

    public bool IsRunning => _isRunning;
    public bool IsEtwKernelModeActive => _etwService.IsRunning;
    public bool IsEtwDnsModeActive => _etwDnsService.IsRunning;
    public GuardPolicy CurrentPolicy => _policy;
    public QuarantineManager Quarantine => _quarantineManager;
    public RecoveryVault Vault => _recoveryVault;
    public AuditLogService AuditLog => _auditLog;
    public ThreatIntelStore ThreatIntel => _intelStore;
    public ThreatScanner Scanner => _scanner;
    public BrowserAndPupCleaner BrowserPupCleaner => _browserPupCleaner;
    public MzkDeepScanner MzkScanner => _mzkScanner;
    public MalwareRemediationService Remediation => _remediationService;
    public NetworkGuardMonitor NetworkGuard => _networkGuard;
    public PersistenceMonitor Persistence => _persistenceMonitor;
    public ProcessController ProcessControl => _processController;
    public ProcessTreeTracker TreeTracker => _treeTracker;
    public CanaryManager Canaries => _canaryManager;
    public BehaviorRiskEngine RiskEngine => _riskEngine;
    public CustomRuleEngine CustomRules => _customRuleEngine;
    public TelemetryMetrics Metrics => _metrics;

    public event Action<SecurityEvent>? EventRecorded;
    public event Action<SecurityEvent>? UserInterventionRequired;
    public event Action<string>? EngineStatusMessage;
    public event Action<string>? DatabaseUpdated;

    public SecurityOrchestrator(
        PolicyStore? policyStore = null,
        ProcessController? processController = null,
        QuarantineManager? quarantineManager = null)
    {
        _policyStore = policyStore ?? new PolicyStore();
        _policy = _policyStore.Load();

        _processController = processController ?? new ProcessController();
        _signatureVerifier = new SignatureVerifier();
        _intelStore = new ThreatIntelStore(_policyStore.BaseDirectory);
        _quarantineManager = quarantineManager ?? new QuarantineManager(_policyStore.BaseDirectory);
        _recoveryVault = new RecoveryVault(_policyStore.BaseDirectory, _policyStore.Signer);
        _auditLog = new AuditLogService(_policyStore.BaseDirectory);
        _treeTracker = new ProcessTreeTracker();
        _riskEngine = new BehaviorRiskEngine();
        _customRuleEngine = new CustomRuleEngine(_policyStore.BaseDirectory, _policyStore.Signer);
        _metrics = new TelemetryMetrics();
        _scanner = new ThreatScanner(_signatureVerifier, _intelStore, _processController);
        _processEvaluator = new ProcessRuleEvaluator(_treeTracker, _intelStore, _customRuleEngine, _metrics);
        _ransomwareDetector = new RansomwareDetector();
        _canaryManager = new CanaryManager();
        _persistenceMonitor = new PersistenceMonitor(_signatureVerifier, () => _policy);
        _browserPupCleaner = new BrowserAndPupCleaner(_intelStore, _policyStore.BaseDirectory, _policyStore.Signer);
        _mzkScanner = new MzkDeepScanner(_scanner, _signatureVerifier, _processController, _persistenceMonitor, _processEvaluator, _browserPupCleaner);
        _credentialGuard = new CredentialAndDllGuard(_signatureVerifier, () => _policy);
        _networkGuard = new NetworkGuardMonitor(_processController, _signatureVerifier, _riskEngine, _intelStore, () => _policy);
        _filelessScriptGuard = new FilelessScriptGuard(() => _policy);
        _downloadUsbGuard = new DownloadAndUsbGuard(_scanner, () => _policy);
        _systemIntegrityGuard = new SystemIntegrityGuard(_policyStore, () => _policy, restored => _policy = restored, _customRuleEngine, _browserPupCleaner);
        _remediationService = new MalwareRemediationService(_processController, _quarantineManager, _auditLog, _policyStore.BaseDirectory, () => _systemIntegrityGuard.RefreshHostsBaseline());
        _clipboardGuard = new ClipboardGuard();
        _etwService = new EtwKernelTelemetryService(
            _processController,
            _signatureVerifier,
            _treeTracker,
            _processEvaluator,
            _ransomwareDetector,
            _canaryManager,
            _credentialGuard,
            _networkGuard,
            _riskEngine,
            () => _policy,
            _metrics);
        _etwDnsService = new EtwDnsTelemetryService(_processController, _networkGuard, () => _policy, _metrics);
        _fallbackMonitor = new FallbackProcessAndFileMonitor(
            _processController,
            _signatureVerifier,
            _processEvaluator,
            _ransomwareDetector,
            _canaryManager,
            () => _policy);

        _etwService.ThreatDetected += HandleDetectedThreat;
        _etwService.TelemetryError += msg => EngineStatusMessage?.Invoke(msg);
        _etwDnsService.ThreatDetected += HandleDetectedThreat;
        _fallbackMonitor.ThreatDetected += HandleDetectedThreat;
        _persistenceMonitor.ThreatDetected += HandleDetectedThreat;
        _credentialGuard.ThreatDetected += HandleDetectedThreat;
        _networkGuard.ThreatDetected += HandleDetectedThreat;
        _filelessScriptGuard.ThreatDetected += HandleDetectedThreat;
        _downloadUsbGuard.ThreatDetected += HandleDetectedThreat;
        _systemIntegrityGuard.ThreatDetected += HandleDetectedThreat;
    }

    public void InspectClipboardText(string? text)
    {
        var alert = _clipboardGuard.EvaluateClipboardText(text, _policy);
        if (alert is not null)
        {
            HandleDetectedThreat(alert);
        }
    }

    public void NotifyUsbDeviceArrival()
    {
        if (IsRunning && _policy.EnableDownloadAndUsbGuard)
        {
            _downloadUsbGuard.NotifyDeviceArrival();
        }
    }

    public void Start()
    {
        lock (_lifecycleLock)
        {
            if (_isRunning) return;

            if (_policy.DeployCanaryFiles && _policy.EnableRansomwareShield)
            {
                _canaryManager.DeployCanaries(_policy.ProtectedFolders);
            }

            bool etwStarted = false;
            bool etwDnsStarted = false;
            if (_policy.EnableEtwTelemetry && ProcessController.IsCurrentProcessElevated())
            {
                etwStarted = _etwService.Start();
                etwDnsStarted = _etwDnsService.Start();
            }

            _fallbackMonitor.Start(processMonitoringHandledByEtw: etwStarted);
            _persistenceMonitor.Start();
            _credentialGuard.StartWatchers();
            _networkGuard.Start(etwHandlesNetwork: etwStarted, etwHandlesDns: etwDnsStarted);
            _filelessScriptGuard.Start();
            _downloadUsbGuard.Start();
            _systemIntegrityGuard.Start();

            if (_policyStore.LastLoadDetectedTampering)
            {
                HandleDetectedThreat(new SecurityEvent
                {
                    Severity = ThreatSeverity.Critical,
                    Category = ThreatCategory.SelfDefenseTamper,
                    ActionTaken = SecurityActionTaken.RolledBack,
                    Title = "자가 방어 경고: 시작 시 정책 파일 외부 변조 감지 및 안전 초기화!",
                    Description = _policyStore.LastTamperReason,
                    TargetPath = _policyStore.PolicyFilePath,
                    RiskScore = 100
                });
            }

            if (_customRuleEngine.LastLoadDetectedTampering)
            {
                HandleDetectedThreat(new SecurityEvent
                {
                    Severity = ThreatSeverity.Critical,
                    Category = ThreatCategory.SelfDefenseTamper,
                    ActionTaken = SecurityActionTaken.RolledBack,
                    Title = "자가 방어 경고: 시작 시 탐지 규칙(rules.json) 외부 변조 감지 및 안전 복구!",
                    Description = _customRuleEngine.LastTamperReason,
                    TargetPath = _customRuleEngine.RulesFilePath,
                    RiskScore = 100
                });
            }

            if (_browserPupCleaner.LastLoadDetectedTampering)
            {
                HandleDetectedThreat(new SecurityEvent
                {
                    Severity = ThreatSeverity.Critical,
                    Category = ThreatCategory.SelfDefenseTamper,
                    ActionTaken = SecurityActionTaken.RolledBack,
                    Title = "자가 방어 경고: 시작 시 PUP 룰(pup_rules.json) 외부 변조 감지 및 안전 복구!",
                    Description = "pup_rules.json의 HMAC 무결성 서명이 일치하지 않아 기본 룰로 복구했습니다.",
                    TargetPath = _browserPupCleaner.PupRulesFilePath,
                    RiskScore = 100
                });
            }

            if (_policy.EnableAutoRecoveryVault)
            {
                if (!PowerProfileHelper.IsBatterySaverActive)
                {
                    _ = Task.Run(RunVaultSnapshotSafely);
                }
                _vaultSyncTimer = new Timer(
                    _ =>
                    {
                        if (PowerProfileHelper.IsBatterySaverActive) return;
                        int tick = Interlocked.Increment(ref _vaultTick);
                        if (PowerProfileHelper.IsOnBatteryPower && (tick & 1) == 1) return; // 30m cadence on battery, 15m on AC
                        RunVaultSnapshotSafely();
                    },
                    null,
                    TimeSpan.FromMinutes(15),
                    TimeSpan.FromMinutes(15));
            }

            if (_policy.EnableMemoryInjectionGuard)
            {
                _memorySweepTimer = new Timer(
                    _ =>
                    {
                        int tick = Interlocked.Increment(ref _memorySweepTick);
                        if (PowerProfileHelper.IsOnBatteryPower && (tick & 1) == 1) return; // 120s cadence on battery, 60s on AC
                        if (Interlocked.Exchange(ref _isSweepingMemory, 1) == 1) return;
                        try { SweepSuspiciousProcessMemory(); }
                        finally { Interlocked.Exchange(ref _isSweepingMemory, 0); }
                    },
                    null,
                    TimeSpan.FromSeconds(45),
                    TimeSpan.FromSeconds(60));
            }

            // Daily (24h) automatic virus & adware DB freshness watchdog:
            // Checks an in-memory timestamp once per hour (<1us CPU, zero network unless >=24h elapsed)
            // so even laptops that sleep/wake across days stay automatically up-to-date.
            _dailyDbSyncTimer = new Timer(
                _ => _ = CheckAndSyncDailyDatabaseAsync(),
                null,
                TimeSpan.FromSeconds(12),
                TimeSpan.FromHours(1));

            _isRunning = true;
            EngineStatusMessage?.Invoke(etwStarted
                ? "엔터프라이즈 9중 방어 + ETW 커널 텔레메트리 활성화됨 (관리자 모드)"
                : "스마트 저마찰 9중 방어 활성화됨 (ETW 커널 텔레메트리는 관리자 승격 시 활성화)");
        }
    }

    private async Task CheckAndSyncDailyDatabaseAsync()
    {
        if (!_isRunning || PowerProfileHelper.IsBatterySaverActive) return;
        if (!_intelStore.IsFullDatabaseSyncDue) return;

        try
        {
            var (hashRes, feedRes) = await _intelStore.SyncFullAntivirusDatabaseAsync();
            if (hashRes.Success || feedRes.Success)
            {
                var msg = $"[자동 일일 DB 갱신 완료] 악성 해시 {_intelStore.TotalBlockedHashCount:N0}개 · 애드웨어/멀웨어 도메인 {_intelStore.TotalBlockedDomainCount:N0}개 · C2 IP {_intelStore.TotalBlockedIpCount:N0}개";
                DatabaseUpdated?.Invoke(msg);
                EngineStatusMessage?.Invoke(msg);
            }
        }
        catch { }
    }

    private void RunVaultSnapshotSafely()
    {
        if (Interlocked.Exchange(ref _isSyncingVault, 1) == 1) return;
        try
        {
            _recoveryVault.SnapshotProtectedFolders(_policy.ProtectedFolders);
        }
        catch { }
        finally
        {
            Interlocked.Exchange(ref _isSyncingVault, 0);
        }
    }

    public void Stop()
    {
        lock (_lifecycleLock)
        {
            if (!_isRunning) return;
            _isRunning = false;

            _vaultSyncTimer?.Dispose();
            _vaultSyncTimer = null;
            _memorySweepTimer?.Dispose();
            _memorySweepTimer = null;
            _dailyDbSyncTimer?.Dispose();
            _dailyDbSyncTimer = null;

            _etwService.Stop();
            _etwDnsService.Stop();
            _fallbackMonitor.Stop();
            _persistenceMonitor.Stop();
            _credentialGuard.StopWatchers();
            _networkGuard.Stop();
            _filelessScriptGuard.Stop();
            _downloadUsbGuard.Stop();
            _systemIntegrityGuard.Stop();

            _activeInterventionPids.Clear();
            _processController.ResumeAllSuspendedProcesses();

            EngineStatusMessage?.Invoke("보안 모니터링 중지됨");
        }
    }

    public void UpdatePolicy(GuardPolicy updatedPolicy)
    {
        lock (_lifecycleLock)
        {
            var prev = _policy;
            var snapshot = updatedPolicy.Clone();
            snapshot.SanitizeAndValidate();
            _policy = snapshot;
            _policyStore.Save(snapshot);

            if (!_isRunning) return;

            if (!snapshot.DeployCanaryFiles || !snapshot.EnableRansomwareShield)
            {
                try { _canaryManager.RemoveCanaries(); } catch { }
            }
            else if (!prev.DeployCanaryFiles || !prev.EnableRansomwareShield)
            {
                try { _canaryManager.DeployCanaries(snapshot.ProtectedFolders); } catch { }
            }

            // Only restart ETW sessions if EnableEtwTelemetry actually changed —
            // never call ResumeAllSuspendedProcesses() on active frozen threats during routine policy edits!
            if (prev.EnableEtwTelemetry != snapshot.EnableEtwTelemetry)
            {
                Stop();
                Start();
            }
        }
    }

    public bool AllowAndResumeProcess(SecurityEvent evt, bool addToWhitelist, bool grantSessionImmunity = true)
    {
        var result = AllowAndResumeProcessDetailed(evt, addToWhitelist, grantSessionImmunity);
        return result.AllCleared && result.AnyResumed;
    }

    public ProcessTreeResumeResult AllowAndResumeProcessDetailed(
        SecurityEvent evt,
        bool addToWhitelist,
        bool grantSessionImmunity = true)
    {
        if (evt.ProcessId > 4 && _sessionAllowedPids.Count > 1024)
        {
            var cutoff = DateTimeOffset.UtcNow.AddMinutes(-30);
            foreach (var kvp in _sessionAllowedPids)
            {
                if (kvp.Value.AllowedAt < cutoff) _sessionAllowedPids.TryRemove(kvp.Key, out _);
            }
        }

        if (addToWhitelist && !string.IsNullOrWhiteSpace(evt.ProcessPath) && !QuarantineManager.IsProtectedSystemOrSelfPath(evt.ProcessPath))
        {
            // Copy-on-write immutable policy swap + SanitizeAndValidate so LOLBins/browsers can never be whitelisted
            var updated = _policy.Clone();
            if (!updated.WhitelistedExecutablePaths.Contains(evt.ProcessPath, StringComparer.OrdinalIgnoreCase))
            {
                updated.WhitelistedExecutablePaths.Add(evt.ProcessPath);
            }
            updated.SanitizeAndValidate();

            bool stillWhitelisted = updated.WhitelistedExecutablePaths.Contains(evt.ProcessPath, StringComparer.OrdinalIgnoreCase);
            bool isTransientBuildOutput = evt.ProcessPath.Contains(@"\bin\Debug\", StringComparison.OrdinalIgnoreCase) ||
                                          evt.ProcessPath.Contains(@"\bin\Release\", StringComparison.OrdinalIgnoreCase) ||
                                          evt.ProcessPath.Contains(@"\obj\", StringComparison.OrdinalIgnoreCase);

            if (stillWhitelisted && !isTransientBuildOutput && File.Exists(evt.ProcessPath))
            {
                try
                {
                    var sha = SignatureVerifier.ComputeSha256(evt.ProcessPath);
                    updated.TrustedBinaryHashes.RemoveAll(h => h.Path.Equals(evt.ProcessPath, StringComparison.OrdinalIgnoreCase));
                    updated.TrustedBinaryHashes.Add(new TrustedBinaryHash(evt.ProcessPath, sha, DateTimeOffset.Now));
                }
                catch { }
            }

            _policy = updated;
            _policyStore.Save(updated);
        }

        // Collect suspended child targets from recorded instances, recorded PIDs, and live tracked descendants
        var fallbackChildPids = new HashSet<int>(evt.SuspendedChildProcessIds);
        foreach (var inst in evt.SuspendedChildInstances)
        {
            if (inst.ProcessId > 4 && inst.ProcessId != evt.ProcessId)
            {
                fallbackChildPids.Add(inst.ProcessId);
            }
        }
        if (evt.ProcessId > 4)
        {
            foreach (var d in _treeTracker.GetDescendantPids(evt.ProcessId))
            {
                if (_processController.IsProcessSuspendedByUs(d))
                {
                    fallbackChildPids.Add(d);
                }
            }
        }

        var resumeResult = _processController.TryResumeProcessTreeDetailed(
            evt.ProcessId,
            evt.ProcessCreationTimeFileTimeUtc,
            evt.SuspendedChildInstances,
            fallbackChildPids);

        // Update root tracking ONLY when root is cleared (resumed or exited/replaced)
        if (!resumeResult.RootStillSuspended)
        {
            if (evt.ProcessId > 4)
            {
                if (grantSessionImmunity)
                {
                    _sessionAllowedPids[evt.ProcessId] = (evt.ProcessPath ?? string.Empty, DateTimeOffset.UtcNow);
                }
                _activeInterventionPids.TryRemove(evt.ProcessId, out _);
                _riskEngine.ClearProcess(evt.ProcessId);
            }
            evt.IsProcessSuspended = false;
        }
        else
        {
            evt.IsProcessSuspended = true;
            if (evt.ProcessId > 4)
            {
                _activeInterventionPids[evt.ProcessId] = 1;
            }
        }

        // Update child tracking ONLY for children that were actually resumed or exited/replaced
        var remainingChildren = new HashSet<int>(resumeResult.RemainingSuspendedChildPids);
        foreach (var childRes in resumeResult.ChildResults)
        {
            if (childRes.Status != ProcessResumeStatus.TransientFailureRetryRequired)
            {
                if (grantSessionImmunity && childRes.Status == ProcessResumeStatus.Resumed)
                {
                    var childPath = _processController.GetExecutablePath(childRes.ProcessId);
                    if (!string.IsNullOrWhiteSpace(childPath))
                    {
                        _sessionAllowedPids[childRes.ProcessId] = (childPath, DateTimeOffset.UtcNow);
                    }
                }
                _activeInterventionPids.TryRemove(childRes.ProcessId, out _);
                _riskEngine.ClearProcess(childRes.ProcessId);
            }
            else
            {
                _activeInterventionPids[childRes.ProcessId] = 1;
            }
        }

        // Clean up any historical child PID that was no longer tracked by ProcessController
        foreach (var childPid in fallbackChildPids)
        {
            if (!remainingChildren.Contains(childPid))
            {
                _activeInterventionPids.TryRemove(childPid, out _);
                _riskEngine.ClearProcess(childPid);
            }
        }

        evt.SuspendedChildProcessIds = remainingChildren.OrderBy(p => p).ToList();
        evt.SuspendedChildInstances = evt.SuspendedChildInstances
            .Where(inst => remainingChildren.Contains(inst.ProcessId))
            .ToList();

        if (resumeResult.AllCleared)
        {
            evt.ActionTaken = SecurityActionTaken.Allowed;
            evt.ContainmentDetail = resumeResult.AnyResumed
                ? "프로세스 및 자식 트리 재개 완료 (허용됨)"
                : "동결 대상 없음 또는 이미 종료됨 (허용됨)";
            if (resumeResult.RootStatus is not null || resumeResult.ChildResults.Count > 0)
            {
                _auditLog.Append(evt);
            }
        }
        else
        {
            var pendingList = new List<int>();
            if (resumeResult.RootStillSuspended) pendingList.Add(evt.ProcessId);
            pendingList.AddRange(resumeResult.RemainingSuspendedChildPids);
            var pendingText = string.Join(", ", pendingList.Distinct());

            evt.ActionTaken = resumeResult.AnyResumed
                ? SecurityActionTaken.PartiallyAllowed
                : SecurityActionTaken.Suspended;
            evt.ContainmentDetail = resumeResult.AnyResumed
                ? $"부분 재개 완료 · 재시도 필요 PID: [{pendingText}]"
                : $"재개 실패 (동결 상태 유지) · 재시도 필요 PID: [{pendingText}]";
            _auditLog.Append(evt);
        }

        return resumeResult;
    }

    public async Task<(bool Success, string Message)> FirewallBlockProcessAsync(SecurityEvent evt)
    {
        var path = !string.IsNullOrWhiteSpace(evt.ProcessPath) ? evt.ProcessPath : evt.TargetPath;
        var result = await FirewallController.BlockOutboundExecutableAsync(path);
        if (result.Success)
        {
            if (evt.ProcessId > 4 || evt.HasAnySuspendedProcess)
            {
                // Network is now blocked at the OS WFP firewall layer; resume the process tree so it doesn't stay frozen in RAM.
                var descendants = evt.ProcessId > 4
                    ? _treeTracker.GetDescendantPids(evt.ProcessId).Concat(evt.SuspendedChildProcessIds).Distinct().ToList()
                    : evt.SuspendedChildProcessIds.ToList();

                var resumeResult = _processController.TryResumeProcessTreeDetailed(
                    evt.ProcessId,
                    evt.ProcessCreationTimeFileTimeUtc,
                    evt.SuspendedChildInstances,
                    descendants);

                var remainingChildren = new HashSet<int>(resumeResult.RemainingSuspendedChildPids);
                foreach (var childPid in descendants)
                {
                    if (remainingChildren.Contains(childPid)) continue;
                    var childPath = _processController.GetExecutablePath(childPid);
                    if (!string.IsNullOrWhiteSpace(childPath))
                    {
                        _sessionAllowedPids[childPid] = (childPath, DateTimeOffset.UtcNow);
                    }
                    _activeInterventionPids.TryRemove(childPid, out _);
                    _riskEngine.ClearProcess(childPid);
                }

                if (!resumeResult.RootStillSuspended && evt.ProcessId > 4)
                {
                    _activeInterventionPids.TryRemove(evt.ProcessId, out _);
                    _riskEngine.ClearProcess(evt.ProcessId);
                    _sessionAllowedPids[evt.ProcessId] = (evt.ProcessPath ?? string.Empty, DateTimeOffset.UtcNow);
                }

                evt.IsProcessSuspended = resumeResult.RootStillSuspended;
                evt.SuspendedChildProcessIds = remainingChildren.OrderBy(p => p).ToList();
                evt.SuspendedChildInstances = evt.SuspendedChildInstances
                    .Where(inst => remainingChildren.Contains(inst.ProcessId))
                    .ToList();
            }
            evt.ActionTaken = SecurityActionTaken.FirewallBlocked;
        }
        return result;
    }

    public bool KillAndQuarantine(SecurityEvent evt) =>
        KillAndQuarantineDetailed(evt).OverallSuccess;

    public KillAndQuarantineResult KillAndQuarantineDetailed(SecurityEvent evt)
    {
        bool hasTargetProcess = evt.ProcessId > 4;
        bool killed = false;
        ProcessTerminationStatus? rootStatus = null;
        bool rootStillSuspended = false;
        var detailParts = new List<string>();
        var handledChildPids = new HashSet<int>();
        var childResults = new List<ProcessTerminationItemResult>();
        var remainingFrozenChildren = new HashSet<int>();
        var retryTerminationChildren = new HashSet<int>();

        void RecordChildTerminationOutcome(ProcessTerminationItemResult childRes)
        {
            childResults.Add(childRes);
            if (childRes.Status == ProcessTerminationStatus.TransientFailureRetryRequired)
            {
                retryTerminationChildren.Add(childRes.ProcessId);
            }

            if (childRes.StillSuspendedByUs)
            {
                // ONLY genuinely frozen children remain in frozen tracking and _activeInterventionPids!
                remainingFrozenChildren.Add(childRes.ProcessId);
                _activeInterventionPids[childRes.ProcessId] = 1;
            }
            else
            {
                // Running (never-frozen) children whose termination failed MUST NOT be marked frozen
                // or silenced in _activeInterventionPids so follow-up telemetry keeps being evaluated.
                _activeInterventionPids.TryRemove(childRes.ProcessId, out _);
                if (childRes.Status != ProcessTerminationStatus.TransientFailureRetryRequired)
                {
                    _riskEngine.ClearProcess(childRes.ProcessId);
                }
            }
        }

        // P1-1 + P1-B: Terminate frozen child instances FIRST using single-handle creation-time verification,
        // preserving tracking ONLY for children that are actually still frozen, while recording termination retries separately.
        foreach (var childInst in evt.SuspendedChildInstances.ToList())
        {
            if (childInst.ProcessId <= 4 || childInst.ProcessId == evt.ProcessId) continue;
            handledChildPids.Add(childInst.ProcessId);
            var childRes = _processController.TryTerminateProcessInstanceDetailed(
                childInst.ProcessId,
                childInst.CreationTimeFileTimeUtc,
                childInst.ExecutablePath);
            RecordChildTerminationOutcome(childRes);
        }

        // For any legacy SuspendedChildProcessIds without an explicit instance record,
        // terminate ONLY if ProcessController still holds a verified creation time or executable path.
        foreach (var suspendedChildPid in evt.SuspendedChildProcessIds.ToList())
        {
            if (suspendedChildPid <= 4 || suspendedChildPid == evt.ProcessId || !handledChildPids.Add(suspendedChildPid))
            {
                continue;
            }
            if (_processController.TryGetTrackedSuspendedInstance(suspendedChildPid, out var trackedChild) &&
                trackedChild is not null &&
                (trackedChild.CreationTimeFileTimeUtc != 0 || !string.IsNullOrWhiteSpace(trackedChild.ExecutablePath)))
            {
                var childRes = _processController.TryTerminateProcessInstanceDetailed(
                    trackedChild.ProcessId,
                    trackedChild.CreationTimeFileTimeUtc,
                    trackedChild.ExecutablePath);
                RecordChildTerminationOutcome(childRes);
                continue;
            }
            else if (_processController.IsProcessSuspendedByUs(suspendedChildPid))
            {
                // Still suspended by us without verifiable instance metadata -> do NOT silently drop tracking!
                RecordChildTerminationOutcome(new ProcessTerminationItemResult(
                    suspendedChildPid,
                    ProcessTerminationStatus.TransientFailureRetryRequired,
                    StillSuspendedByUs: true,
                    "인스턴스 식별 정보 부족으로 종료 보류 — 재개 또는 수동 확인 필요"));
                continue;
            }

            _activeInterventionPids.TryRemove(suspendedChildPid, out _);
            _riskEngine.ClearProcess(suspendedChildPid);
        }

        if (hasTargetProcess)
        {
            // P1-#3: 3-way root identity precheck (Matched / ExitedOrReplaced / LookupFailed)
            // so transient query/permission errors NEVER misclassify a still-frozen parent as exited/replaced!
            var rootPrecheck = (evt.ProcessCreationTimeFileTimeUtc != 0 || !string.IsNullOrWhiteSpace(evt.ProcessPath))
                ? _processController.VerifyProcessInstanceIdentity(
                    evt.ProcessId,
                    evt.ProcessCreationTimeFileTimeUtc,
                    evt.ProcessPath)
                : ProcessIdentityVerificationStatus.Matched;

            if (rootPrecheck == ProcessIdentityVerificationStatus.Matched)
            {
                foreach (var descPid in _treeTracker.GetDescendantPids(evt.ProcessId))
                {
                    if (descPid <= 4 || descPid == evt.ProcessId || !handledChildPids.Add(descPid))
                    {
                        continue;
                    }

                    if (_processController.TryInspectProcessInstanceIdentity(descPid, out var descIdentity, out var descLookup))
                    {
                        if (descIdentity is not null)
                        {
                            // A genuine live child cannot have been created before its parent.
                            if (evt.ProcessCreationTimeFileTimeUtc != 0 &&
                                descIdentity.CreationTimeFileTimeUtc != 0 &&
                                descIdentity.CreationTimeFileTimeUtc < evt.ProcessCreationTimeFileTimeUtc)
                            {
                                continue;
                            }
                            var descRes = _processController.TryTerminateProcessInstanceDetailed(
                                descPid,
                                descIdentity.CreationTimeFileTimeUtc,
                                descIdentity.ExecutablePath);
                            RecordChildTerminationOutcome(descRes);
                            continue;
                        }
                    }
                    else if (descLookup == ProcessIdentityVerificationStatus.LookupFailed)
                    {
                        RecordChildTerminationOutcome(new ProcessTerminationItemResult(
                            descPid,
                            ProcessTerminationStatus.TransientFailureRetryRequired,
                            StillSuspendedByUs: _processController.IsProcessSuspendedByUs(descPid),
                            "자식 신원 조회 실패 — 종료 보류(재시도 필요)"));
                        continue;
                    }

                    if (!_processController.IsProcessSuspendedByUs(descPid))
                    {
                        _activeInterventionPids.TryRemove(descPid, out _);
                        _riskEngine.ClearProcess(descPid);
                    }
                }

                if (evt.ProcessCreationTimeFileTimeUtc != 0 || !string.IsNullOrWhiteSpace(evt.ProcessPath))
                {
                    var rootRes = _processController.TryTerminateProcessInstanceDetailed(
                        evt.ProcessId,
                        evt.ProcessCreationTimeFileTimeUtc,
                        evt.ProcessPath);
                    rootStatus = rootRes.Status;
                    killed = rootRes.Status == ProcessTerminationStatus.Terminated;
                    rootStillSuspended = rootRes.StillSuspendedByUs;
                }
                else
                {
                    killed = _processController.TryTerminateProcess(evt.ProcessId);
                    rootStatus = killed ? ProcessTerminationStatus.Terminated : ProcessTerminationStatus.AlreadyExitedOrReplaced;
                    rootStillSuspended = !killed && _processController.IsProcessSuspendedByUs(evt.ProcessId);
                }
            }
            else if (rootPrecheck == ProcessIdentityVerificationStatus.LookupFailed)
            {
                // Transient identity/path lookup failure: hold BOTH root and live descendant termination,
                // and preserve existing frozen state so user can retry cleanly!
                rootStatus = ProcessTerminationStatus.TransientFailureRetryRequired;
                killed = false;
                rootStillSuspended = _processController.IsProcessSuspendedByUs(evt.ProcessId);
            }
            else
            {
                rootStatus = ProcessTerminationStatus.AlreadyExitedOrReplaced;
                killed = false;
                rootStillSuspended = false;
            }

            if (!rootStillSuspended)
            {
                _activeInterventionPids.TryRemove(evt.ProcessId, out _);
                if (rootStatus != ProcessTerminationStatus.TransientFailureRetryRequired)
                {
                    _riskEngine.ClearProcess(evt.ProcessId);
                }
            }
            else
            {
                _activeInterventionPids[evt.ProcessId] = 1;
            }

            evt.ProcessTerminationSucceeded = killed;
            detailParts.Add(killed
                ? $"프로세스(PID {evt.ProcessId}) 종료 완료"
                : (rootStatus == ProcessTerminationStatus.TransientFailureRetryRequired
                    ? (rootStillSuspended
                        ? $"프로세스(PID {evt.ProcessId}) 신원 조회/종료 실패(동결 유지 — 재시도 필요)"
                        : $"프로세스(PID {evt.ProcessId}) 종료 실패(실행 중 — 재시도 필요)")
                    : $"프로세스(PID {evt.ProcessId}) 종료 실패/미실행"));
        }

        evt.IsProcessSuspended = rootStillSuspended;
        evt.SuspendedChildProcessIds = remainingFrozenChildren.OrderBy(p => p).ToList();
        evt.SuspendedChildInstances = evt.SuspendedChildInstances
            .Where(inst => remainingFrozenChildren.Contains(inst.ProcessId))
            .ToList();
        evt.PendingTerminationRetryChildPids = retryTerminationChildren.OrderBy(p => p).ToList();

        if (remainingFrozenChildren.Count > 0)
        {
            detailParts.Add($"자식 종료 실패(동결 유지 · 재시도/재개 필요) PID: [{string.Join(", ", remainingFrozenChildren.OrderBy(p => p))}]");
        }
        var unfrozenRetryChildren = retryTerminationChildren.Except(remainingFrozenChildren).OrderBy(p => p).ToList();
        if (unfrozenRetryChildren.Count > 0)
        {
            detailParts.Add($"미동결 자식 종료 실패(실행 중 · 재시도 필요) PID: [{string.Join(", ", unfrozenRetryChildren)}]");
        }

        // TargetPath is only the malicious file for static file / DLL / USB drops.
        // For behavioral process attacks (Ransomware, CredentialAccess, SupplyChain, etc.),
        // TargetPath is the victim user document or credential file — NEVER quarantine victim user files!
        bool targetIsMaliciousArtifact = evt.Category is
            ThreatCategory.DllHijacking or
            ThreatCategory.UsbOrDownloadThreat or
            ThreatCategory.StaticMalware;

        var fileToQuarantine = targetIsMaliciousArtifact &&
                               !string.IsNullOrWhiteSpace(evt.TargetPath) &&
                               File.Exists(evt.TargetPath)
            ? evt.TargetPath
            : (!string.IsNullOrWhiteSpace(evt.ProcessPath) && File.Exists(evt.ProcessPath) ? evt.ProcessPath : string.Empty);

        bool quarantineRemovedOrScheduled = false;
        QuarantineDisposition? qDisposition = null;
        if (!string.IsNullOrWhiteSpace(fileToQuarantine) &&
            !IsProtectedWindowsSystemBinary(fileToQuarantine) &&
            !IsProtectedUserDocumentOrCredential(fileToQuarantine))
        {
            try
            {
                var qEntry = _quarantineManager.QuarantineFile(fileToQuarantine, evt.Title);
                qDisposition = qEntry.Disposition;
                evt.QuarantineDisposition = qEntry.Disposition;
                switch (qEntry.Disposition)
                {
                    case QuarantineDisposition.RemovedImmediately:
                        quarantineRemovedOrScheduled = true;
                        evt.ActionTaken = SecurityActionTaken.Quarantined;
                        detailParts.Add("원본 제거 및 AES-256-GCM 격리 완료");
                        break;
                    case QuarantineDisposition.ScheduledDeleteOnReboot:
                        quarantineRemovedOrScheduled = true;
                        evt.ActionTaken = SecurityActionTaken.QuarantinePendingReboot;
                        detailParts.Add("격리 사본 보관 완료 · 원본은 재부팅 시 OS 자동 삭제 예약됨");
                        break;
                    case QuarantineDisposition.CopyOnlyOriginalLocked:
                        quarantineRemovedOrScheduled = false;
                        detailParts.Add("원본 파일 잠금으로 격리 사본만 보관됨 (원본 미제거)");
                        break;
                }
            }
            catch (Exception ex)
            {
                detailParts.Add($"격리 실패({ex.Message})");
            }
        }

        bool rolledBack = false;
        if (evt.Category == ThreatCategory.SystemIntegrityTamper &&
            !string.IsNullOrWhiteSpace(evt.TargetPath) &&
            evt.TargetPath.Contains("Internet Settings", StringComparison.OrdinalIgnoreCase))
        {
            if (SystemIntegrityGuard.TryDisableHijackedProxy())
            {
                rolledBack = true;
                detailParts.Add("프록시 설정 롤백 완료");
                if (!quarantineRemovedOrScheduled) evt.ActionTaken = SecurityActionTaken.RolledBack;
            }
        }

        if (evt.Category == ThreatCategory.Persistence && !string.IsNullOrWhiteSpace(evt.TargetPath))
        {
            var idx = evt.TargetPath.LastIndexOf('\\');
            if (idx > 0)
            {
                var loc = evt.TargetPath[..idx];
                var name = evt.TargetPath[(idx + 1)..];
                if (PersistenceMonitor.TryRollbackEntry(loc, name))
                {
                    rolledBack = true;
                    detailParts.Add("지속성 항목 롤백 완료");
                    if (!quarantineRemovedOrScheduled) evt.ActionTaken = SecurityActionTaken.RolledBack;
                }
            }
        }

        if (detailParts.Count > 0)
        {
            evt.ContainmentDetail = string.Join(" | ", detailParts);
        }

        bool hasPendingFrozen = rootStillSuspended || remainingFrozenChildren.Count > 0;
        bool hasTerminationRetry = rootStatus == ProcessTerminationStatus.TransientFailureRetryRequired || retryTerminationChildren.Count > 0;
        bool hasUnresolved = hasPendingFrozen || hasTerminationRetry;
        bool overallSuccess;
        if (quarantineRemovedOrScheduled || rolledBack)
        {
            overallSuccess = !hasUnresolved;
        }
        else if (hasTargetProcess && killed)
        {
            evt.ActionTaken = SecurityActionTaken.Terminated;
            overallSuccess = !hasUnresolved;
        }
        else
        {
            evt.ActionTaken = qDisposition == QuarantineDisposition.CopyOnlyOriginalLocked
                ? SecurityActionTaken.QuarantineCopyOnly
                : (hasPendingFrozen ? SecurityActionTaken.Suspended : SecurityActionTaken.Logged);
            overallSuccess = false;
        }

        if (hasUnresolved)
        {
            _auditLog.Append(evt);
        }

        return new KillAndQuarantineResult(
            RootTerminated: killed,
            RootStatus: rootStatus,
            RootStillSuspended: rootStillSuspended,
            ChildResults: childResults,
            QuarantineRemovedOrScheduled: quarantineRemovedOrScheduled,
            QuarantineDisposition: qDisposition,
            RolledBack: rolledBack,
            OverallSuccess: overallSuccess);
    }

    private void SweepSuspiciousProcessMemory()
    {
        try
        {
            var policy = _policy;
            if (!policy.EnableMemoryInjectionGuard) return;

            // Zero-overhead targeted sweep: inspect ONLY PIDs already carrying risk score
            // or spawned from high-risk user-writable drop paths instead of enumerating all 250+ OS processes!
            var candidatePids = new HashSet<int>(_riskEngine.GetTrackedPids());
            var knownPaths = new Dictionary<int, (string Name, string Path)>();
            foreach (var node in _treeTracker.GetHighRiskDropPathNodes())
            {
                candidatePids.Add(node.Pid);
                knownPaths[node.Pid] = (node.Name, node.Path);
            }

            if (candidatePids.Count == 0)
            {
                return; // Zero OS syscalls when idle!
            }

            var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";
            foreach (var pid in candidatePids)
            {
                try
                {
                    if (pid <= 4 || pid == Environment.ProcessId || InternalHelperProcessRegistry.IsInternalHelper(pid)) continue;

                    var livePath = _processController.GetExecutablePath(pid);
                    if (string.IsNullOrWhiteSpace(livePath))
                    {
                        // Process already exited — prune stale tracking and never flag an exited temp installer!
                        _treeTracker.RecordStop(pid);
                        _riskEngine.ClearProcess(pid);
                        continue;
                    }

                    string path = livePath;
                    string name = knownPaths.TryGetValue(pid, out var known) && !string.IsNullOrWhiteSpace(known.Name)
                        ? known.Name
                        : Path.GetFileNameWithoutExtension(path);

                    if (string.IsNullOrWhiteSpace(path) || QuarantineManager.IsProtectedSystemOrSelfPath(path))
                    {
                        continue;
                    }

                    var sig = _signatureVerifier.VerifyFile(path);
                    var alert = MemoryInspectionGuard.EvaluateProcess(pid, name, path, sig, policy);
                    if (alert is not null)
                    {
                        HandleDetectedThreat(alert);
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    public void ProcessSecurityEvent(SecurityEvent evt) => HandleDetectedThreat(evt);

    private void HandleDetectedThreat(SecurityEvent evt)
    {
        var now = DateTimeOffset.UtcNow;

        // Enrich missing ProcessPath / CreationTime / Signature up front so whitelist, PID-reuse verification,
        // ThreatPromptWindow UI, and Strict-mode signature checks always operate on complete metadata.
        if (evt.ProcessId > 4 && (string.IsNullOrWhiteSpace(evt.ProcessPath) || evt.ProcessCreationTimeFileTimeUtc == 0))
        {
            if (_processController.TryGetProcessInstanceIdentity(evt.ProcessId, out var liveIdentity) && liveIdentity is not null)
            {
                if (evt.ProcessCreationTimeFileTimeUtc == 0 && liveIdentity.CreationTimeFileTimeUtc != 0)
                {
                    evt.ProcessCreationTimeFileTimeUtc = liveIdentity.CreationTimeFileTimeUtc;
                }
                if (string.IsNullOrWhiteSpace(evt.ProcessPath) && !string.IsNullOrWhiteSpace(liveIdentity.ExecutablePath))
                {
                    evt.ProcessPath = liveIdentity.ExecutablePath;
                }
            }
            else if (string.IsNullOrWhiteSpace(evt.ProcessPath))
            {
                evt.ProcessPath = _processController.GetExecutablePath(evt.ProcessId);
            }
        }

        // 1. Respect session-level user "Allow Once" ONLY if the PID still belongs to the exact same executable path
        // and has not expired (prevents Windows PID Reuse from granting immunity to a newly spawned malicious process!).
        if (evt.ProcessId > 4 && _sessionAllowedPids.TryGetValue(evt.ProcessId, out var allowedEntry))
        {
            bool pathMatches = !string.IsNullOrWhiteSpace(allowedEntry.ProcessPath) &&
                               !string.IsNullOrWhiteSpace(evt.ProcessPath)
                ? allowedEntry.ProcessPath.Equals(evt.ProcessPath, StringComparison.OrdinalIgnoreCase)
                : string.IsNullOrWhiteSpace(allowedEntry.ProcessPath) && string.IsNullOrWhiteSpace(evt.ProcessPath);
            if (pathMatches && (now - allowedEntry.AllowedAt).TotalMinutes < 30)
            {
                return;
            }
            _sessionAllowedPids.TryRemove(evt.ProcessId, out _);
        }

        // Never let WhitelistedExecutablePaths silence BinaryTampering (SHA-256 hash mismatch on a trusted binary!),
        // Masquerading, StaticMalware, or ThreatIntel IOC hits!
        bool overridesWhitelist = evt.Category is ThreatCategory.BinaryTampering or ThreatCategory.StaticMalware or ThreatCategory.Masquerading ||
                                  evt.RiskSignals.Any(s =>
                                      s.StartsWith("ThreatIntel", StringComparison.OrdinalIgnoreCase) ||
                                      s.StartsWith("EtwDnsIoc", StringComparison.OrdinalIgnoreCase));
        if (!overridesWhitelist &&
            !string.IsNullOrWhiteSpace(evt.ProcessPath) &&
            _policy.WhitelistedExecutablePaths.Contains(evt.ProcessPath, StringComparer.OrdinalIgnoreCase))
        {
            return;
        }

        if (evt.Signature is null && !string.IsNullOrWhiteSpace(evt.ProcessPath) && File.Exists(evt.ProcessPath))
        {
            evt.Signature = _signatureVerifier.VerifyFile(evt.ProcessPath);
        }

        // Respect policy.WhitelistedPublishers on validly signed non-LOLBin processes (unless tampered/masquerading/user-IOC)
        if (!overridesWhitelist &&
            evt.Signature is { IsSigned: true } validSig &&
            !string.IsNullOrWhiteSpace(validSig.PublisherName) &&
            _policy.WhitelistedPublishers.Any(pub => validSig.PublisherName.Contains(pub, StringComparison.OrdinalIgnoreCase)))
        {
            var exeFile = Path.GetFileName(evt.ProcessPath ?? evt.ProcessName ?? string.Empty);
            bool isAbusableSystemShell = exeFile.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase) ||
                                         exeFile.Equals("pwsh.exe", StringComparison.OrdinalIgnoreCase) ||
                                         exeFile.Equals("cmd.exe", StringComparison.OrdinalIgnoreCase) ||
                                         exeFile.Equals("mshta.exe", StringComparison.OrdinalIgnoreCase) ||
                                         exeFile.Equals("wscript.exe", StringComparison.OrdinalIgnoreCase) ||
                                         exeFile.Equals("cscript.exe", StringComparison.OrdinalIgnoreCase) ||
                                         exeFile.Equals("rundll32.exe", StringComparison.OrdinalIgnoreCase) ||
                                         exeFile.Equals("regsvr32.exe", StringComparison.OrdinalIgnoreCase) ||
                                         exeFile.Equals("certutil.exe", StringComparison.OrdinalIgnoreCase) ||
                                         exeFile.Equals("bitsadmin.exe", StringComparison.OrdinalIgnoreCase) ||
                                         exeFile.Equals("installutil.exe", StringComparison.OrdinalIgnoreCase) ||
                                         exeFile.Equals("msbuild.exe", StringComparison.OrdinalIgnoreCase) ||
                                         exeFile.Equals("ntdsutil.exe", StringComparison.OrdinalIgnoreCase) ||
                                         exeFile.Equals("nltest.exe", StringComparison.OrdinalIgnoreCase) ||
                                         exeFile.Equals("vssadmin.exe", StringComparison.OrdinalIgnoreCase) ||
                                         exeFile.Equals("wbadmin.exe", StringComparison.OrdinalIgnoreCase) ||
                                         exeFile.Equals("bcdedit.exe", StringComparison.OrdinalIgnoreCase) ||
                                         exeFile.Equals("wmic.exe", StringComparison.OrdinalIgnoreCase);

            // Never allow WhitelistedPublishers to silence explicit Ransomware Canary/Extension or Custom SOC Rule hits,
            // while protecting trusted Microsoft/Google/Mozilla apps from behavioral/network false freezes!
            if (!isAbusableSystemShell &&
                evt.Category is not (ThreatCategory.Ransomware or ThreatCategory.PrivilegeEscalation or ThreatCategory.DocumentExploit) &&
                !evt.RiskSignals.Any(s => s.StartsWith("CustomRule:", StringComparison.OrdinalIgnoreCase)))
            {
                if (evt.Severity >= ThreatSeverity.High)
                {
                    evt.ActionTaken = SecurityActionTaken.Logged;
                    _auditLog.Append(evt);
                    try { EventRecorded?.Invoke(evt); } catch { }
                }
                return;
            }
        }

        // 2. If this PID (or an ancestor that already suspended it) is awaiting user decision, do NOT stack duplicate prompts!
        if (evt.ProcessId > 4 &&
            (_activeInterventionPids.ContainsKey(evt.ProcessId) || _processController.IsProcessSuspendedByUs(evt.ProcessId)))
        {
            return;
        }

        evt.EnsureMitrePopulated();
        if (string.IsNullOrWhiteSpace(evt.ProcessAncestry) && evt.ProcessId > 4)
        {
            evt.ProcessAncestry = _treeTracker.FormatAncestryString(evt.ProcessId);
        }

        int baseWeight = evt.RiskScore > 0 ? evt.RiskScore : evt.Severity switch
        {
            ThreatSeverity.Critical => 90,
            ThreatSeverity.High => 75,
            ThreatSeverity.Medium => 40,
            _ => 20
        };

        // Atomic 5-second deduplication gate: allows strictly one concurrent caller per key,
        // still admits a higher-risk escalation for the same key, and prunes only expired keys!
        var dedupKey = $"{evt.Category}|{evt.ProcessId}|{evt.TargetPath}|{evt.RemoteEndpoint}|{evt.Title}";
        if (!TryAcquireEventDedupGate(dedupKey, baseWeight, now))
        {
            return;
        }

        RiskAssessment assessment;
        if (evt.IsRiskAlreadyCorrelated)
        {
            assessment = _riskEngine.GetCurrentAssessment(
                evt.ProcessId,
                baseWeight,
                evt.RiskSignals,
                _policy.SmartLowFrictionMode);
        }
        else
        {
            var firstSig = evt.RiskSignals.FirstOrDefault();
            int sepIdx = firstSig?.IndexOfAny(new[] { ':', '(' }) ?? -1;
            var primarySignal = sepIdx > 0 ? firstSig![..sepIdx] : evt.Category.ToString();

            assessment = _riskEngine.RecordSignal(
                evt.ProcessId,
                primarySignal,
                baseWeight,
                marksCredentialAccess: evt.Category == ThreatCategory.CredentialAccess,
                marksExternalNetwork: evt.Category is ThreatCategory.NetworkAnomaly or ThreatCategory.Exfiltration,
                smartLowFrictionMode: _policy.SmartLowFrictionMode);
        }

        evt.RiskScore = Math.Max(evt.RiskScore, assessment.TotalScore);
        foreach (var sig in assessment.Signals)
        {
            if (!evt.RiskSignals.Contains(sig)) evt.RiskSignals.Add(sig);
        }

        if (evt.RiskScore >= 75) evt.Severity = ThreatSeverity.Critical;
        _metrics.IncrementThreatDetected();

        if (_policy.Mode == ProtectionMode.MonitorOnly)
        {
            evt.ActionTaken = SecurityActionTaken.Logged;
            _auditLog.Append(evt);
            try { EventRecorded?.Invoke(evt); } catch { }
            return;
        }

        bool isCriticalProtectedProc = evt.ProcessId > 4 && _processController.IsCriticalProtectedProcess(evt.ProcessId);

        if (assessment.ShouldFreezeProcess && evt.ProcessId > 4 && !isCriticalProtectedProc)
        {
            var descendants = _treeTracker.GetDescendantPids(evt.ProcessId);

            if (_policy.Mode == ProtectionMode.Strict &&
                (evt.Signature is null || !evt.Signature.IsSigned))
            {
                var strictFreeze = _processController.TrySuspendProcessTreeDetailed(evt.ProcessId, descendants);
                if (strictFreeze.RootInstance is { CreationTimeFileTimeUtc: > 0 })
                {
                    evt.ProcessCreationTimeFileTimeUtc = strictFreeze.RootInstance.CreationTimeFileTimeUtc;
                }
                evt.IsProcessSuspended = strictFreeze.RootSuspended;
                evt.SuspendedChildProcessIds = strictFreeze.SuspendedChildPids.ToList();
                evt.SuspendedChildInstances = strictFreeze.SuspendedChildInstances?.ToList() ?? new List<ProcessInstanceIdentity>();
                evt.AttemptedChildFreezeCount = strictFreeze.AttemptedChildCount;
                if (strictFreeze.AnySuspended)
                {
                    _metrics.IncrementProcessFrozen();
                }

                var strictKillResult = KillAndQuarantineDetailed(evt);
                if (!string.IsNullOrWhiteSpace(evt.ProcessPath) && File.Exists(evt.ProcessPath))
                {
                    _ = FirewallController.BlockOutboundExecutableAsync(evt.ProcessPath);
                }
                if (!strictKillResult.HasAnyPendingFrozenProcess && !strictKillResult.HasAnyTerminationRetryRequired)
                {
                    _auditLog.Append(evt);
                }
                try { EventRecorded?.Invoke(evt); } catch { }

                // P1-#1: If Strict-mode auto-kill leaves any frozen process behind, hand off to the user prompt queue
                // so the user can retry termination or resume instead of leaving it stranded frozen!
                if (strictKillResult.HasAnyPendingFrozenProcess || evt.HasAnySuspendedProcess)
                {
                    try { UserInterventionRequired?.Invoke(evt); } catch { }
                }
                return;
            }

            var freezeResult = _processController.TrySuspendProcessTreeDetailed(evt.ProcessId, descendants);
            if (freezeResult.RootInstance is { CreationTimeFileTimeUtc: > 0 })
            {
                evt.ProcessCreationTimeFileTimeUtc = freezeResult.RootInstance.CreationTimeFileTimeUtc;
            }
            evt.IsProcessSuspended = freezeResult.RootSuspended;
            evt.SuspendedChildProcessIds = freezeResult.SuspendedChildPids.ToList();
            evt.SuspendedChildInstances = freezeResult.SuspendedChildInstances?.ToList() ?? new List<ProcessInstanceIdentity>();
            evt.AttemptedChildFreezeCount = freezeResult.AttemptedChildCount;

            if (freezeResult.AnySuspended)
            {
                _metrics.IncrementProcessFrozen();
                // Track ONLY children that were actually frozen — never blind telemetry for failed/running children!
                foreach (var frozenChildPid in freezeResult.SuspendedChildPids)
                {
                    _activeInterventionPids.TryAdd(frozenChildPid, 1);
                }
            }

            if (freezeResult.RootSuspended)
            {
                evt.ActionTaken = SecurityActionTaken.Suspended;
                evt.ContainmentDetail = freezeResult.AttemptedChildCount > 0
                    ? $"부모 동결 완료 · 자식 {freezeResult.SuspendedChildPids.Count}/{freezeResult.AttemptedChildCount}개 동결"
                    : "프로세스 즉시 동결 완료";
            }
            else if (freezeResult.SuspendedChildPids.Count > 0)
            {
                evt.ActionTaken = SecurityActionTaken.Logged;
                evt.ContainmentDetail = $"부분 동결 주의: 부모(PID {evt.ProcessId}) 실행 중 · 자식 {freezeResult.SuspendedChildPids.Count}/{freezeResult.AttemptedChildCount}개만 동결됨";
            }
        }

        if (evt.Category == ThreatCategory.DllHijacking &&
            _policy.Mode == ProtectionMode.Strict &&
            evt.Signature?.IsSigned != true &&
            File.Exists(evt.TargetPath) &&
            !QuarantineManager.IsProtectedSystemOrSelfPath(evt.TargetPath))
        {
            try
            {
                var qEntry = _quarantineManager.QuarantineFile(evt.TargetPath, evt.Title);
                evt.QuarantineDisposition = qEntry.Disposition;
                evt.ActionTaken = qEntry.Disposition switch
                {
                    QuarantineDisposition.RemovedImmediately => SecurityActionTaken.Quarantined,
                    QuarantineDisposition.ScheduledDeleteOnReboot => SecurityActionTaken.QuarantinePendingReboot,
                    _ => SecurityActionTaken.QuarantineCopyOnly
                };
            }
            catch { }
        }

        _auditLog.Append(evt);
        try { EventRecorded?.Invoke(evt); } catch { }

        // Never pop modal process-kill prompts on critical unfreezable Windows OS processes (e.g. svchost.exe, explorer.exe, PhoneExperienceHost.exe)
        // or ProcessId == 0 informational clipboard/Defender events where no process/artifact intervention applies!
        bool hasActionableNonProcessTarget = evt.Category is ThreatCategory.Persistence or ThreatCategory.SystemIntegrityTamper or ThreatCategory.SelfDefenseTamper or ThreatCategory.DllHijacking or ThreatCategory.UsbOrDownloadThreat;
        if (assessment.ShouldPromptUser && !isCriticalProtectedProc && (evt.ProcessId > 4 || hasActionableNonProcessTarget))
        {
            if (evt.ProcessId <= 4 || _activeInterventionPids.TryAdd(evt.ProcessId, 1))
            {
                try { UserInterventionRequired?.Invoke(evt); } catch { }
            }
        }
    }

    private bool TryAcquireEventDedupGate(string dedupKey, int incomingRiskScore, DateTimeOffset now)
    {
        lock (_dedupLock)
        {
            if (_dedupCache.TryGetValue(dedupKey, out var existing) &&
                (now - existing.LastSeen).TotalSeconds < 5)
            {
                if (incomingRiskScore > existing.LastRiskScore)
                {
                    _dedupCache[dedupKey] = (now, incomingRiskScore);
                    return true;
                }
                return false;
            }

            _dedupCache[dedupKey] = (now, incomingRiskScore);

            if (_dedupCache.Count > 1000)
            {
                var cutoff = now.AddSeconds(-5);
                var expiredKeys = new List<string>();
                foreach (var kvp in _dedupCache)
                {
                    if (kvp.Value.LastSeen < cutoff)
                    {
                        expiredKeys.Add(kvp.Key);
                    }
                }
                foreach (var k in expiredKeys)
                {
                    _dedupCache.Remove(k);
                }

                // If burst traffic still exceeds cap within a single 5s window, evict only the oldest entries
                if (_dedupCache.Count > 2000)
                {
                    var oldest = _dedupCache
                        .OrderBy(k => k.Value.LastSeen)
                        .Take(_dedupCache.Count - 1000)
                        .Select(k => k.Key)
                        .ToList();
                    foreach (var k in oldest)
                    {
                        _dedupCache.Remove(k);
                    }
                }
            }

            return true;
        }
    }

    private static bool IsProtectedWindowsSystemBinary(string path) =>
        QuarantineManager.IsProtectedSystemOrSelfPath(path);

    private bool IsProtectedUserDocumentOrCredential(string path)
    {
        if (_canaryManager.IsCanaryPath(path))
        {
            return true;
        }

        if (ProcessRuleEvaluator.IsProtectedHostIdeProcess(path))
        {
            return true;
        }

        if (path.Contains(@"\.ssh\", StringComparison.OrdinalIgnoreCase) ||
            path.Contains(@"\.aws\", StringComparison.OrdinalIgnoreCase) ||
            path.Contains(@"\.kube\", StringComparison.OrdinalIgnoreCase) ||
            path.Contains(@"\.azure\", StringComparison.OrdinalIgnoreCase) ||
            path.Contains(@"\User Data\", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var ext = Path.GetExtension(path).ToLowerInvariant();
        bool isExecutableOrScriptArtifact = ext is ".exe" or ".dll" or ".scr" or ".com" or ".sys" or ".ocx"
            or ".msi" or ".ps1" or ".bat" or ".cmd" or ".vbs" or ".js" or ".hta" or ".lnk"
            or ".chm" or ".iso" or ".vhd" or ".vhdx" or ".img" or ".zip";

        return !isExecutableOrScriptArtifact;
    }

    public void Dispose()
    {
        Stop();
        _etwService.Dispose();
        _etwDnsService.Dispose();
        _fallbackMonitor.Dispose();
        _persistenceMonitor.Dispose();
        _credentialGuard.Dispose();
        _networkGuard.Dispose();
        _filelessScriptGuard.Dispose();
        _downloadUsbGuard.Dispose();
        _systemIntegrityGuard.Dispose();
    }
}
