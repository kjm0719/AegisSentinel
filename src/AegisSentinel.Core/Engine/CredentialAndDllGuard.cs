using AegisSentinel.Core.Models;
using AegisSentinel.Core.Services;

namespace AegisSentinel.Core.Engine;

public sealed class CredentialAndDllGuard : IDisposable
{
    private static readonly string[] SensitiveBrowserFiles =
    {
        string.Concat("Login ", "Data"),
        "Cookies",
        "Web Data",
        string.Concat("Local ", "State"),
        "logins.json",
        "key4.db",
        "cookies.sqlite"
    };

    private static readonly string[] SensitiveDeveloperPaths =
    {
        @"\.ssh\id_rsa",
        @"\.ssh\id_ed25519",
        @"\.ssh\id_ecdsa",
        @"\.ssh\id_dsa",
        @"\.aws\credentials",
        @"\.azure\accessTokens.json",
        @"\.kube\config",
        @"\nkbihfbeogaeaoehlefnkodbefgpgknn\", // MetaMask Chrome ext
        @"\bfnaelmomeimhlpmgjnjophhpkkoljpa\",  // Phantom Chrome ext
        @"\Solana\id.json",
        @"\.config\solana\id.json",
        @"\AppData\Roaming\Exodus\",
        @"\AppData\Roaming\Electrum\"
    };

    // Script engines abused in Lazarus fake-interview / npm / PyPI campaigns (BeaverTail / OtterCookie)
    private static readonly HashSet<string> ScriptStealerRuntimes = new(StringComparer.OrdinalIgnoreCase)
    {
        "node.exe", "python.exe", "pythonw.exe", "deno.exe", "bun.exe", "wscript.exe", "cscript.exe", "mshta.exe", "luajit.exe"
    };

    private static readonly string[] AuthorizedBrowserExecutables =
    {
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe", "whale.exe",
        "elevation_service.exe", "identity_helper.exe", "pwahelper.exe", "chrmstp.exe",
        "GoogleUpdate.exe", "MicrosoftEdgeUpdate.exe"
    };

    private static readonly string[] AuthorizedDevExecutables =
    {
        "ssh.exe", "ssh-agent.exe", "ssh-keygen.exe", "scp.exe", "sftp.exe",
        "git.exe", "git-remote-https.exe",
        "aws.exe", "az.exe", "kubectl.exe", "kubelogin.exe", "helm.exe", "k9s.exe", "terraform.exe", "pulumi.exe",
        "docker.exe", "code.exe", "cursor.exe", "devenv.exe", "rider64.exe", "idea64.exe", "winscp.exe",
        "explorer.exe"
    };

    private readonly SignatureVerifier _signatureVerifier;
    private readonly Func<GuardPolicy> _policyProvider;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly object _watcherSync = new();

    public event Action<SecurityEvent>? ThreatDetected;

    public CredentialAndDllGuard(SignatureVerifier signatureVerifier, Func<GuardPolicy> policyProvider)
    {
        _signatureVerifier = signatureVerifier;
        _policyProvider = policyProvider;
    }

    public void StartWatchers()
    {
        lock (_watcherSync)
        {
            StopWatchers();

            foreach (var dir in GetBrowserBinaryDirectories())
            {
                AddDllHijackWatcher(dir);
            }
        }
    }

    public void StopWatchers()
    {
        lock (_watcherSync)
        {
            foreach (var watcher in _watchers)
            {
                watcher.EnableRaisingEvents = false;
                watcher.Dispose();
            }
            _watchers.Clear();
        }
    }

    /// <summary>
    /// Evaluates whether a DLL dropped or loaded inside a browser/watched app folder is an unsigned hijack attempt.
    /// </summary>
    public SecurityEvent? EvaluateDllDropOrLoad(
        int pid,
        string processName,
        string processPath,
        string dllPath,
        GuardPolicy policy)
    {
        if (!policy.EnableCredentialAndDllGuard || string.IsNullOrWhiteSpace(dllPath))
        {
            return null;
        }

        if (!dllPath.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var isBrowserDir = IsInsideBrowserBinaryDirectory(dllPath);
        var isWatchedLauncher = !string.IsNullOrWhiteSpace(processName) &&
            ProcessRuleEvaluator.IsWatchedLauncherOrRenderer(
                Path.GetFileNameWithoutExtension(processName),
                processPath,
                policy);

        if (!isBrowserDir && !isWatchedLauncher)
        {
            return null;
        }

        // Ignore legitimate Windows system DLLs (EXCEPT world-writable C:\Windows\Temp and C:\Windows\Tasks!)
        if (!string.IsNullOrEmpty(CachedWindowsDir) &&
            dllPath.StartsWith(CachedWindowsDir, StringComparison.OrdinalIgnoreCase) &&
            !dllPath.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) &&
            !dllPath.Contains(@"\Tasks\", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var sig = _signatureVerifier.VerifyFile(dllPath);
        bool isHighRiskDrop = ProcessRuleEvaluator.IsHighRiskDropPath(dllPath);

        // 1. Inside protected system browser binary directories (Chrome/Edge/Firefox Program Files),
        // any unsigned or tampered DLL or drop-path DLL is a side-loading hijack attempt.
        // 2. For watched game/app launchers, games legitimately ship unsigned 3rd-party helper DLLs in their own
        // install directory; only flag if the signature is tampered OR the DLL is loaded from a high-risk drop/temp path!
        bool isSuspiciousDll = isBrowserDir
            ? (sig.Status is SignatureStatus.Unsigned or SignatureStatus.InvalidOrTampered || isHighRiskDrop)
            : (sig.Status == SignatureStatus.InvalidOrTampered || (!sig.IsSigned && isHighRiskDrop));

        if (isSuspiciousDll)
        {
            return new SecurityEvent
            {
                Severity = ThreatSeverity.Critical,
                Category = ThreatCategory.DllHijacking,
                ActionTaken = SecurityActionTaken.Logged,
                Title = isBrowserDir
                    ? "브라우저 DLL 하이재킹 의심 파일 탐지"
                    : "런처/앱 임시경로 미서명·변조 DLL 로드 탐지",
                Description = $"'{dllPath}' ({sig.DisplayLabel})가 '{(string.IsNullOrEmpty(processName) ? "브라우저 폴더" : processName)}'에 드롭/로드되었습니다.",
                ProcessId = pid,
                ProcessName = processName,
                ProcessPath = processPath,
                TargetPath = dllPath,
                RiskScore = 90,
                RiskSignals = new List<string> { isBrowserDir ? "BrowserDllHijack(+90)" : "RiskyPathDllSideLoad(+90)" },
                Signature = sig
            };
        }

        return null;
    }

    /// <summary>
    /// Evaluates whether an unauthorized process is reading or writing sensitive credentials (browser DB, SSH/AWS keys, crypto wallets).
    /// </summary>
    public SecurityEvent? EvaluateSensitiveFileAccess(
        int pid,
        string processName,
        string processPath,
        string targetPath,
        GuardPolicy policy)
    {
        if (!policy.EnableCredentialAndDllGuard ||
            pid <= 4 ||
            pid == Environment.ProcessId ||
            InternalHelperProcessRegistry.IsInternalHelper(pid) ||
            ProcessRuleEvaluator.IsProtectedHostIdeProcess(processPath))
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(targetPath))
        {
            return null;
        }

        // Ignore benign SSH public keys (.pub), known_hosts, and config
        if (targetPath.EndsWith(".pub", StringComparison.OrdinalIgnoreCase) ||
            targetPath.EndsWith("known_hosts", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        if (!string.IsNullOrWhiteSpace(processPath) &&
            policy.WhitelistedExecutablePaths.Contains(processPath, StringComparer.OrdinalIgnoreCase))
        {
            return null;
        }

        var normalizedTarget = targetPath.Replace('/', '\\');
        var fileName = Path.GetFileName(normalizedTarget);
        var exeName = Path.GetFileName(string.IsNullOrWhiteSpace(processPath) ? processName : processPath);
        if (!exeName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(exeName))
        {
            exeName += ".exe";
        }

        // 1. Browser password/cookie database access by non-browser process
        bool isBrowserDb = SensitiveBrowserFiles.Contains(fileName, StringComparer.OrdinalIgnoreCase) &&
                           (normalizedTarget.Contains(@"\Google\Chrome\User Data\", StringComparison.OrdinalIgnoreCase) ||
                            normalizedTarget.Contains(@"\Microsoft\Edge\User Data\", StringComparison.OrdinalIgnoreCase) ||
                            normalizedTarget.Contains(@"\Mozilla\Firefox\Profiles\", StringComparison.OrdinalIgnoreCase) ||
                            normalizedTarget.Contains(@"\BraveSoftware\Brave-Browser\User Data\", StringComparison.OrdinalIgnoreCase) ||
                            normalizedTarget.Contains(@"\Naver\Naver Whale\User Data\", StringComparison.OrdinalIgnoreCase) ||
                            normalizedTarget.Contains(@"\Vivaldi\User Data\", StringComparison.OrdinalIgnoreCase) ||
                            normalizedTarget.Contains(@"\Opera Software\Opera Stable\", StringComparison.OrdinalIgnoreCase));

        bool isAuthorizedBrowser = AuthorizedBrowserExecutables.Contains(exeName, StringComparer.OrdinalIgnoreCase) &&
                                   (string.IsNullOrWhiteSpace(processPath) ||
                                    (!ProcessRuleEvaluator.IsHighRiskDropPath(processPath) &&
                                     (!File.Exists(processPath) || _signatureVerifier.VerifyFile(processPath).IsSigned)));

        if (isBrowserDb && !isAuthorizedBrowser)
        {
            // Ignore Windows Defender / SearchIndexer / Explorer thumbnailers
            if (IsTrustedWindowsServiceProcess(exeName, processPath))
            {
                return null;
            }

            var sig = File.Exists(processPath)
                ? _signatureVerifier.VerifyFile(processPath)
                : new SignatureInfo(SignatureStatus.Unknown, string.Empty);

            return new SecurityEvent
            {
                Severity = ThreatSeverity.Critical,
                Category = ThreatCategory.CredentialAccess,
                ActionTaken = SecurityActionTaken.Logged,
                Title = "비인가 프로세스의 브라우저 자격증명(쿠키/비밀번호) 접근 탐지",
                Description = $"브라우저가 아닌 '{exeName}' (PID {pid})가 '{normalizedTarget}'에 접근했습니다.",
                ProcessId = pid,
                ProcessName = processName,
                ProcessPath = processPath,
                TargetPath = normalizedTarget,
                RiskScore = 95,
                RiskSignals = new List<string> { "BrowserCredentialDbTheft(+95)" },
                Signature = sig
            };
        }

        // 2. Developer SSH/Cloud/Crypto Wallet access by untrusted/launcher processes
        bool isDevOrWalletSecret = SensitiveDeveloperPaths.Any(p =>
            normalizedTarget.Contains(p, StringComparison.OrdinalIgnoreCase));

        bool isAuthorizedDevTool = AuthorizedDevExecutables.Contains(exeName, StringComparer.OrdinalIgnoreCase) &&
                                   (string.IsNullOrWhiteSpace(processPath) ||
                                    (!ProcessRuleEvaluator.IsHighRiskDropPath(processPath) &&
                                     (!exeName.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase) ||
                                      processPath.StartsWith(CachedWindowsDir, StringComparison.OrdinalIgnoreCase))));

        if (isDevOrWalletSecret && !isAuthorizedDevTool)
        {
            if (IsTrustedWindowsServiceProcess(exeName, processPath))
            {
                return null;
            }

            var sig = File.Exists(processPath)
                ? _signatureVerifier.VerifyFile(processPath)
                : new SignatureInfo(SignatureStatus.Unknown, string.Empty);

            bool isLauncherOrRisky = !sig.IsSigned ||
                ScriptStealerRuntimes.Contains(exeName) ||
                ProcessRuleEvaluator.IsUserWritableRiskyPath(processPath) ||
                ProcessRuleEvaluator.IsWatchedLauncherOrRenderer(Path.GetFileNameWithoutExtension(exeName), processPath, policy);

            if (isLauncherOrRisky)
            {
                return new SecurityEvent
                {
                    Severity = ThreatSeverity.Critical,
                    Category = ThreatCategory.CredentialAccess,
                    ActionTaken = SecurityActionTaken.Logged,
                    Title = "개발자 키/클라우드 자격증명/가상자산 지갑 무단 접근 탐지",
                    Description = $"의심 프로세스 '{exeName}' (PID {pid})가 민감 경로 '{normalizedTarget}'에 접근했습니다.",
                    ProcessId = pid,
                    ProcessName = processName,
                    ProcessPath = processPath,
                    TargetPath = normalizedTarget,
                    RiskScore = 95,
                    RiskSignals = new List<string> { "DeveloperOrWalletSecretAccess(+95)" },
                    Signature = sig
                };
            }
        }

        return null;
    }

    private void AddDllHijackWatcher(string directory)
    {
        try
        {
            if (!Directory.Exists(directory))
            {
                return;
            }

            var watcher = new FileSystemWatcher(directory, "*.dll")
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                EnableRaisingEvents = true
            };

            watcher.Created += (_, e) => OnDllChanged(e.FullPath);
            watcher.Renamed += (_, e) => OnDllChanged(e.FullPath);
            _watchers.Add(watcher);
        }
        catch
        {
            // Ignore directories that cannot be watched.
        }
    }

    private void OnDllChanged(string dllPath)
    {
        _ = Task.Run(async () =>
        {
            try
            {
                // Debounce browser auto-updaters (GoogleUpdate/MicrosoftEdgeUpdate) writing new DLL bytes to disk
                await Task.Delay(500);
                if (!File.Exists(dllPath)) return;

                var policy = _policyProvider();
                var pids = ProcessController.GetProcessesLockingFile(dllPath);
                int pid = pids.FirstOrDefault();
                var alert = EvaluateDllDropOrLoad(pid, string.Empty, string.Empty, dllPath, policy);
                if (alert is not null)
                {
                    ThreatDetected?.Invoke(alert);
                }
            }
            catch
            {
                // Ignore transient file access errors during drop.
            }
        });
    }

    private static readonly string CachedWindowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";
    private static readonly string CachedDefenderDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender").TrimEnd('\\') + "\\";
    private static readonly string CachedDefenderProgramDataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows Defender").TrimEnd('\\') + "\\";
    private static readonly Lazy<string[]> CachedBrowserDirs = new(BuildBrowserBinaryDirectories);

    private static bool IsTrustedWindowsServiceProcess(string exeName, string processPath)
    {
        if (exeName.Equals("MsMpEng.exe", StringComparison.OrdinalIgnoreCase) ||
            exeName.Equals("MpCmdRun.exe", StringComparison.OrdinalIgnoreCase) ||
            exeName.Equals("NisSrv.exe", StringComparison.OrdinalIgnoreCase) ||
            exeName.Equals("SearchProtocolHost.exe", StringComparison.OrdinalIgnoreCase) ||
            exeName.Equals("SearchFilterHost.exe", StringComparison.OrdinalIgnoreCase) ||
            exeName.Equals("SearchIndexer.exe", StringComparison.OrdinalIgnoreCase) ||
            exeName.Equals("TiWorker.exe", StringComparison.OrdinalIgnoreCase) ||
            exeName.Equals("TrustedInstaller.exe", StringComparison.OrdinalIgnoreCase) ||
            exeName.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase) ||
            exeName.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(processPath) && exeName.Equals("MsMpEng.exe", StringComparison.OrdinalIgnoreCase))
            {
                return true; // PPL-protected Defender service when queried from non-elevated context
            }

            return (CachedWindowsDir.Length > 1 && processPath.StartsWith(CachedWindowsDir, StringComparison.OrdinalIgnoreCase)) ||
                   (CachedDefenderDir.Length > 1 && processPath.StartsWith(CachedDefenderDir, StringComparison.OrdinalIgnoreCase)) ||
                   (CachedDefenderProgramDataDir.Length > 1 && processPath.StartsWith(CachedDefenderProgramDataDir, StringComparison.OrdinalIgnoreCase));
        }

        return false;
    }

    private static string[] BuildBrowserBinaryDirectories()
    {
        var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var candidates = new[]
        {
            Path.Combine(pf, "Google", "Chrome", "Application"),
            Path.Combine(pf86, "Google", "Chrome", "Application"),
            Path.Combine(localApp, "Google", "Chrome", "Application"),
            Path.Combine(pf86, "Microsoft", "Edge", "Application"),
            Path.Combine(pf, "Microsoft", "Edge", "Application"),
            Path.Combine(pf, "Mozilla Firefox"),
            Path.Combine(pf86, "Mozilla Firefox"),
            Path.Combine(pf, "Naver", "Naver Whale", "Application"),
            Path.Combine(pf86, "Naver", "Naver Whale", "Application")
        };

        return candidates.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static IEnumerable<string> GetBrowserBinaryDirectories() => CachedBrowserDirs.Value;

    private static bool IsInsideBrowserBinaryDirectory(string filePath)
    {
        foreach (var dir in CachedBrowserDirs.Value)
        {
            var prefix = dir.EndsWith('\\') ? dir : dir + "\\";
            if (filePath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    public void Dispose()
    {
        StopWatchers();
    }
}
