using System.Text.Json.Serialization;

namespace AegisSentinel.Core.Models;

public enum ThreatSeverity
{
    Info,
    Low,
    Medium,
    High,
    Critical
}

public enum ThreatCategory
{
    SupplyChain,
    Ransomware,
    DllHijacking,
    CredentialAccess,
    Persistence,
    UnsignedExecution,
    NetworkAnomaly,
    Exfiltration,
    FilelessScript,
    BinaryTampering,
    MemoryInjection,
    UsbOrDownloadThreat,
    StaticMalware,
    Masquerading,
    SelfDefenseTamper,
    ClipboardAttack,
    SystemIntegrityTamper,
    DocumentExploit,
    PrivilegeEscalation,
    SystemHardening
}

public enum SecurityActionTaken
{
    Logged = 0,
    Suspended = 1,
    Terminated = 2,
    Quarantined = 3,
    FirewallBlocked = 4,
    RolledBack = 5,
    Allowed = 6,
    QuarantinePendingReboot = 7,
    QuarantineCopyOnly = 8,
    PartiallyAllowed = 9
}

public enum QuarantineDisposition
{
    RemovedImmediately = 0,
    ScheduledDeleteOnReboot = 1,
    CopyOnlyOriginalLocked = 2,
    PendingOriginalRemoval = 3,
    OriginalChangedNotRemoved = 4
}

public enum QuarantineRestoreStatus
{
    Restored,
    DestinationConflict,
    IntegrityCheckFailed,
    NotFoundOrInvalid,
    WriteFailed,
    RestoredButRebootDeleteCancelFailed
}

public sealed record QuarantineRestoreResult(
    QuarantineRestoreStatus Status,
    string DestinationPath,
    string Message)
{
    public bool Success => Status == QuarantineRestoreStatus.Restored;
}

public sealed record ProcessInstanceIdentity(
    int ProcessId,
    long CreationTimeFileTimeUtc,
    string ExecutablePath = "");

public enum ProcessResumeStatus
{
    Resumed,
    AlreadyExitedOrReplaced,
    TransientFailureRetryRequired
}

public sealed record ProcessResumeItemResult(
    int ProcessId,
    ProcessResumeStatus Status,
    string Detail = "");

public sealed record ProcessTreeResumeResult(
    int RootPid,
    ProcessResumeStatus? RootStatus,
    IReadOnlyList<ProcessResumeItemResult> ChildResults)
{
    public IReadOnlyList<int> RemainingSuspendedChildPids =>
        ChildResults
            .Where(r => r.Status == ProcessResumeStatus.TransientFailureRetryRequired)
            .Select(r => r.ProcessId)
            .ToList();

    public bool RootStillSuspended => RootStatus == ProcessResumeStatus.TransientFailureRetryRequired;
    public bool HasAnyPendingRetry => RootStillSuspended || RemainingSuspendedChildPids.Count > 0;
    public bool AnyResumed =>
        RootStatus == ProcessResumeStatus.Resumed ||
        ChildResults.Any(r => r.Status == ProcessResumeStatus.Resumed);
    public bool AllCleared => !HasAnyPendingRetry;
}

public enum ProcessIdentityVerificationStatus
{
    Matched,
    ExitedOrReplaced,
    LookupFailed
}

public enum ProcessTerminationStatus
{
    Terminated,
    AlreadyExitedOrReplaced,
    ProtectedProcessSkipped,
    TransientFailureRetryRequired
}

public sealed record ProcessTerminationItemResult(
    int ProcessId,
    ProcessTerminationStatus Status,
    bool StillSuspendedByUs,
    string Detail = "");

public sealed record KillAndQuarantineResult(
    bool RootTerminated,
    ProcessTerminationStatus? RootStatus,
    bool RootStillSuspended,
    IReadOnlyList<ProcessTerminationItemResult> ChildResults,
    bool QuarantineRemovedOrScheduled,
    QuarantineDisposition? QuarantineDisposition,
    bool RolledBack,
    bool OverallSuccess)
{
    public IReadOnlyList<int> RemainingSuspendedChildPids =>
        ChildResults
            .Where(r => r.StillSuspendedByUs)
            .Select(r => r.ProcessId)
            .Distinct()
            .ToList();

    public IReadOnlyList<int> RetryRequiredChildPids =>
        ChildResults
            .Where(r => r.Status == ProcessTerminationStatus.TransientFailureRetryRequired)
            .Select(r => r.ProcessId)
            .Distinct()
            .ToList();

    public bool HasAnyPendingFrozenProcess =>
        RootStillSuspended || RemainingSuspendedChildPids.Count > 0;

    public bool HasAnyTerminationRetryRequired =>
        RootStatus == ProcessTerminationStatus.TransientFailureRetryRequired || RetryRequiredChildPids.Count > 0;
}

public enum SignatureStatus
{
    Unknown,
    TrustedMicrosoft,
    TrustedVendor,
    Unsigned,
    InvalidOrTampered
}

public enum ProtectionMode
{
    /// <summary>Low-friction smart correlation: silently tracks low risk, freezes &amp; prompts on high-confidence threats.</summary>
    Balanced,
    /// <summary>Automatically terminate, quarantine, and firewall-block high-confidence unsigned threats.</summary>
    Strict,
    /// <summary>Observe and alert without suspending or terminating processes.</summary>
    MonitorOnly
}

public sealed record SignatureInfo(
    SignatureStatus Status,
    string PublisherName,
    string Thumbprint = "",
    string? ErrorMessage = null)
{
    public bool IsSigned => Status is SignatureStatus.TrustedMicrosoft or SignatureStatus.TrustedVendor;

    public string DisplayLabel => Status switch
    {
        SignatureStatus.TrustedMicrosoft => $"신뢰됨 (Microsoft: {PublisherName})",
        SignatureStatus.TrustedVendor => $"서명됨 ({PublisherName})",
        SignatureStatus.Unsigned => "미서명 (Unsigned)",
        SignatureStatus.InvalidOrTampered => $"서명 손상/위변조 ({ErrorMessage ?? "Invalid"})",
        _ => "확인 불가"
    };
}

public sealed class SecurityEvent
{
    public const int CurrentSchemaVersion = 2;

    public int SchemaVersion { get; set; }
    public string Id { get; init; } = Guid.NewGuid().ToString("N")[..12];
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.Now;
    public ThreatSeverity Severity { get; set; }
    public ThreatCategory Category { get; init; }
    public SecurityActionTaken ActionTaken { get; set; }
    public string Title { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public string MitreTechniqueId { get; set; } = string.Empty;
    public string MitreTactic { get; set; } = string.Empty;
    public int ProcessId { get; init; }
    public long ProcessCreationTimeFileTimeUtc { get; set; }
    public string ProcessName { get; init; } = string.Empty;
    public string ProcessPath { get; set; } = string.Empty;
    public int ParentProcessId { get; init; }
    public string ParentProcessName { get; init; } = string.Empty;
    public string ProcessAncestry { get; set; } = string.Empty;
    public string CommandLine { get; init; } = string.Empty;
    public string TargetPath { get; init; } = string.Empty;
    public string RemoteEndpoint { get; init; } = string.Empty;
    public string RemoteDomain { get; init; } = string.Empty;
    public int RiskScore { get; set; }
    public List<string> RiskSignals { get; init; } = new();
    public SignatureInfo? Signature { get; set; }
    public bool IsProcessSuspended { get; set; }
    public List<int> SuspendedChildProcessIds { get; set; } = new();
    public List<ProcessInstanceIdentity> SuspendedChildInstances { get; set; } = new();
    public List<int> PendingTerminationRetryChildPids { get; set; } = new();
    public int AttemptedChildFreezeCount { get; set; }
    public bool? ProcessTerminationSucceeded { get; set; }
    public QuarantineDisposition? QuarantineDisposition { get; set; }
    public string ContainmentDetail { get; set; } = string.Empty;
    public bool IsRiskAlreadyCorrelated { get; set; }
    public bool HasAnySuspendedProcess =>
        IsProcessSuspended || SuspendedChildProcessIds.Count > 0 || SuspendedChildInstances.Count > 0;
    public bool CanIntervene => ProcessId > 4 && (HasAnySuspendedProcess || !string.IsNullOrEmpty(TargetPath) || !string.IsNullOrEmpty(ProcessPath));

    public void EnsureMitrePopulated()
    {
        if (string.IsNullOrWhiteSpace(MitreTechniqueId))
        {
            var m = MitreAttackCatalog.Resolve(Category, Title);
            MitreTechniqueId = m.Id;
            MitreTactic = m.Tactic;
        }
    }
}

public sealed class ProcessEvaluationContext
{
    public int ProcessId { get; init; }
    public string ProcessName { get; init; } = string.Empty;
    public string ProcessPath { get; init; } = string.Empty;
    public string CommandLine { get; init; } = string.Empty;
    public int ParentProcessId { get; init; }
    public string ParentProcessName { get; init; } = string.Empty;
    public string ParentProcessPath { get; init; } = string.Empty;
    public string AncestryChain { get; init; } = string.Empty;
    public SignatureInfo Signature { get; init; } = new(SignatureStatus.Unknown, string.Empty);
}

public sealed record TrustedBinaryHash(
    string Path,
    string Sha256,
    DateTimeOffset ApprovedAt);

public sealed class GuardPolicy
{
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public ProtectionMode Mode { get; set; } = ProtectionMode.Balanced;

    public bool SmartLowFrictionMode { get; set; } = true;
    public bool EnableProcessSupplyChainGuard { get; set; } = true;
    public bool EnableRansomwareShield { get; set; } = true;
    public bool EnableCredentialAndDllGuard { get; set; } = true;
    public bool EnablePersistenceGuard { get; set; } = true;
    public bool EnableNetworkGuard { get; set; } = true;
    public bool EnableFilelessScriptGuard { get; set; } = true;
    public bool EnableMemoryInjectionGuard { get; set; } = true;
    public bool EnableDownloadAndUsbGuard { get; set; } = true;
    public bool EnableSystemIntegrityGuard { get; set; } = true;
    public bool EnableClipboardGuard { get; set; } = true;
    public bool EnableAutoRecoveryVault { get; set; } = true;
    public bool EnableEtwTelemetry { get; set; } = true;
    public bool DeployCanaryFiles { get; set; } = true;
    public int RapidWriteThresholdPer3Sec { get; set; } = 18;
    public string VirusTotalApiKey { get; set; } = string.Empty;

    public List<string> ProtectedFolders { get; set; } = new();
    public List<string> WatchedLauncherProcesses { get; set; } = new();
    public List<string> WhitelistedExecutablePaths { get; set; } = new();
    public List<TrustedBinaryHash> TrustedBinaryHashes { get; set; } = new();
    public List<string> WhitelistedPublishers { get; set; } = new();

    /// <summary>
    /// Creates an isolated deep copy of this policy so updates can be swapped atomically
    /// without mutating Lists while background ETW/monitoring threads enumerate them.
    /// </summary>
    public GuardPolicy Clone() => new()
    {
        Mode = Mode,
        SmartLowFrictionMode = SmartLowFrictionMode,
        EnableProcessSupplyChainGuard = EnableProcessSupplyChainGuard,
        EnableRansomwareShield = EnableRansomwareShield,
        EnableCredentialAndDllGuard = EnableCredentialAndDllGuard,
        EnablePersistenceGuard = EnablePersistenceGuard,
        EnableNetworkGuard = EnableNetworkGuard,
        EnableFilelessScriptGuard = EnableFilelessScriptGuard,
        EnableMemoryInjectionGuard = EnableMemoryInjectionGuard,
        EnableDownloadAndUsbGuard = EnableDownloadAndUsbGuard,
        EnableSystemIntegrityGuard = EnableSystemIntegrityGuard,
        EnableClipboardGuard = EnableClipboardGuard,
        EnableAutoRecoveryVault = EnableAutoRecoveryVault,
        EnableEtwTelemetry = EnableEtwTelemetry,
        DeployCanaryFiles = DeployCanaryFiles,
        RapidWriteThresholdPer3Sec = RapidWriteThresholdPer3Sec,
        VirusTotalApiKey = VirusTotalApiKey,
        ProtectedFolders = new List<string>(ProtectedFolders ?? new List<string>()),
        WatchedLauncherProcesses = new List<string>(WatchedLauncherProcesses ?? new List<string>()),
        WhitelistedExecutablePaths = new List<string>(WhitelistedExecutablePaths ?? new List<string>()),
        TrustedBinaryHashes = new List<TrustedBinaryHash>(TrustedBinaryHashes ?? new List<TrustedBinaryHash>()),
        WhitelistedPublishers = new List<string>(WhitelistedPublishers ?? new List<string>())
    };

    private static readonly HashSet<string> DisallowedWhitelistLolBins = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "wscript.exe", "cscript.exe",
        "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "installutil.exe", "msbuild.exe",
        "sc.exe", "reg.exe", "schtasks.exe", "vssadmin.exe", "wbadmin.exe", "bcdedit.exe",
        "wmic.exe", "net.exe", "net1.exe", "wevtutil.exe", "curl.exe", "msiexec.exe", "fodhelper.exe",
        "chrome.exe", "msedge.exe", "brave.exe", "whale.exe", "firefox.exe"
    };

    /// <summary>
    /// Sharp-Edge Configuration Cliff defense: clamps numeric thresholds to safe bounds
    /// and rejects dangerous root/LOLBin whitelist entries that would silently disable security.
    /// </summary>
    public void SanitizeAndValidate()
    {
        RapidWriteThresholdPer3Sec = Math.Clamp(RapidWriteThresholdPer3Sec, 5, 200);
        ProtectedFolders ??= new List<string>();
        WatchedLauncherProcesses ??= new List<string>();
        WhitelistedExecutablePaths ??= new List<string>();
        TrustedBinaryHashes ??= new List<TrustedBinaryHash>();
        WhitelistedPublishers ??= new List<string>();
        VirusTotalApiKey ??= string.Empty;

        WhitelistedExecutablePaths = WhitelistedExecutablePaths
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(p => p.Trim())
            .Where(p =>
            {
                if (p.Length <= 3 || p.EndsWith(@":\", StringComparison.Ordinal)) return false; // Never whitelist whole drive root
                var fileName = Path.GetFileName(p);
                return !DisallowedWhitelistLolBins.Contains(fileName);
            })
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public static GuardPolicy CreateDefault()
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var folders = new List<string>();
        AddIfNotEmpty(folders, Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
        AddIfNotEmpty(folders, Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
        AddIfNotEmpty(folders, Environment.GetFolderPath(Environment.SpecialFolder.MyPictures));
        if (!string.IsNullOrWhiteSpace(userProfile))
        {
            AddIfNotEmpty(folders, Path.Combine(userProfile, "Downloads"));
            AddIfNotEmpty(folders, Path.Combine(userProfile, ".ssh"));
            AddIfNotEmpty(folders, Path.Combine(userProfile, ".aws"));
        }

        return new GuardPolicy
        {
            Mode = ProtectionMode.Balanced,
            SmartLowFrictionMode = true,
            ProtectedFolders = folders,
            WatchedLauncherProcesses = new List<string>
            {
                "nikke_launcher",
                "nikke",
                "intl_service",
                "tbs_browser",
                "cefsharp.browsersubprocess",
                "qtwebengineprocess",
                "steamwebhelper",
                "epicwebhelper",
                "riotclientservices",
                "riotclientux",
                "battlenet",
                "launcher",
                "magicline",
                "veraport",
                "touchen",
                "ipinside",
                "inisafe",
                "crossex",
                "innorix",
                "anysign",
                "delfino",
                "kslauncher"
            },
            WhitelistedPublishers = new List<string>
            {
                "Microsoft Corporation",
                "Microsoft Windows",
                "Google LLC",
                "Mozilla Corporation"
            }
        };
    }

    private static void AddIfNotEmpty(List<string> list, string? path)
    {
        if (!string.IsNullOrWhiteSpace(path) && !list.Contains(path, StringComparer.OrdinalIgnoreCase))
        {
            list.Add(path);
        }
    }
}

public sealed record QuarantineEntry(
    string Id,
    string OriginalPath,
    string QuarantineFilePath,
    DateTimeOffset QuarantinedAt,
    string Reason,
    string Sha256,
    long FileSize,
    QuarantineDisposition Disposition = QuarantineDisposition.RemovedImmediately,
    string EncryptionFormat = "AES-256-GCM");

public sealed record VaultSnapshotEntry(
    string Id,
    string OriginalPath,
    string SnapshotPath,
    DateTimeOffset CapturedAt,
    string Sha256,
    long FileSize);

public sealed record PersistenceEntry(
    string SourceLocation,
    string Category,
    string Name,
    string Value,
    string ExtractedExecutablePath,
    SignatureInfo? Signature = null);

public sealed record ActiveNetworkConnection(
    int ProcessId,
    string ProcessName,
    string ProcessPath,
    string RemoteIp,
    int RemotePort,
    string RemoteDomain,
    string SignatureLabel,
    int RiskScore);

public sealed record FirewallRuleInfo(
    string RuleName,
    string ProgramPath,
    string Direction,
    string Action);

public sealed record PeAnalysisResult(
    bool IsValidPe,
    bool Is64Bit,
    bool HasRwxSection,
    bool HasPackerSectionName,
    double MaxExecutableSectionEntropy,
    IReadOnlyList<string> SectionNames,
    IReadOnlyList<string> SuspiciousApiHits,
    int HeuristicScore,
    string Summary);

public sealed record ScanFinding(
    string FilePath,
    string Sha256,
    int RiskScore,
    ThreatSeverity Severity,
    SignatureInfo Signature,
    PeAnalysisResult? PeInfo,
    IReadOnlyList<string> Reasons,
    bool HasMarkOfTheWeb);

public sealed record ThreatIntelDatabase(
    List<string> BlockedSha256Hashes,
    List<string> BlockedIpAddresses,
    List<string> BlockedDomains,
    DateTimeOffset? LastFeedSyncUtc = null,
    List<string>? FeedBlockedIpAddresses = null,
    List<string>? FeedBlockedDomains = null);

public sealed record HardeningStatus(
    bool IsElevated,
    bool DefenderRealTimeEnabled,
    bool ControlledFolderAccessEnabled,
    bool NetworkProtectionEnabled,
    bool PuaProtectionEnabled,
    bool LsaProtectionEnabled,
    bool TamperProtectionEnabled,
    bool MemoryIntegrityHvciEnabled,
    bool ScriptBlockLoggingEnabled,
    int ActiveAsrRuleCount,
    bool ElevatedScheduledTaskEnabled,
    IReadOnlyList<string> CfaProtectedFolders,
    string? ErrorMessage = null)
{
    public int SecurityPostureScore
    {
        get
        {
            int score = 0;
            if (DefenderRealTimeEnabled) score += 20;
            if (TamperProtectionEnabled) score += 12;
            if (ControlledFolderAccessEnabled) score += 15;
            if (NetworkProtectionEnabled) score += 10;
            if (PuaProtectionEnabled) score += 5;
            if (MemoryIntegrityHvciEnabled) score += 10;
            if (LsaProtectionEnabled) score += 8;
            if (ScriptBlockLoggingEnabled) score += 5;
            if (ActiveAsrRuleCount > 0) score += Math.Min(10, ActiveAsrRuleCount * 2);
            if (IsElevated) score += 5;
            return Math.Clamp(score, 0, 100);
        }
    }
}
