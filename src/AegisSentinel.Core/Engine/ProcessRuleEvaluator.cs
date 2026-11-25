using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.RegularExpressions;
using AegisSentinel.Core.Models;
using AegisSentinel.Core.Services;

namespace AegisSentinel.Core.Engine;

public sealed class ProcessRuleEvaluator
{
    private static readonly HashSet<string> DangerousChildBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "curl.exe",
        "wget.exe",
        "tinyget.exe",
        "luajit.exe",
        "schtasks.exe",
        "vssadmin.exe",
        "wbadmin.exe",
        "bcdedit.exe"
    };

    private static readonly HashSet<string> SystemOnlyWindowsBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe",
        "lsass.exe",
        "csrss.exe",
        "smss.exe",
        "wininit.exe",
        "services.exe",
        "taskhostw.exe",
        "explorer.exe"
    };

    private static readonly HashSet<string> ProtectedLolBinOriginalNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "mshta.exe",
        "certutil.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "wscript.exe",
        "cscript.exe",
        "bitsadmin.exe"
    };

    private static readonly HashSet<string> BrowserBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "vivaldi.exe", "whale.exe"
    };

    // Document viewers targeted by North Korean APTs (HWP, Hword, HWP Equation Editor gbb.exe, MS Office, PDF, CHM hh.exe)
    private static readonly HashSet<string> DocumentViewerParents = new(StringComparer.OrdinalIgnoreCase)
    {
        "hwp", "hword", "gbb", "hncupdate",
        "winword", "excel", "powerpnt", "mspub",
        "acrord32", "acrobat", "foxitreader", "foxitpdfreader",
        "hh"
    };

    // Windows auto-elevating binaries abused for UAC Bypass (T1548.002)
    private static readonly HashSet<string> UacAutoElevateParents = new(StringComparer.OrdinalIgnoreCase)
    {
        "fodhelper", "computerdefaults", "eventvwr", "sdclt", "cmstp", "wsreset", "slui"
    };

    private static readonly HashSet<string> LegitimateDevDebuggerParents = new(StringComparer.OrdinalIgnoreCase)
    {
        "code", "devenv", "rider64", "idea64", "webstorm64", "pycharm64", "node", "dotnet", "pytest", "python",
        "chromedriver", "msedgedriver", "chrome", "msedge", "brave", "java", "javaw"
    };

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(1500);

    private static readonly Regex DoubleExtensionRegex = new(
        @"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|zip|rar|hwp|hwpx)\.(exe|scr|bat|cmd|vbs|js|ps1|hta|lnk)$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled, RegexTimeout);

    private static readonly Regex EncodedCommandExtractRegex = new(
        @"(?:^|\s)(?:-e|-ec|-en|-enc|-enco|-encod|-encode|-encoded|-encodedc|-encodedco|-encodedcom|-encodedcomm|-encodedcomma|-encodedcomman|-encodedcommand)\s+([A-Za-z0-9+/]{16,}={0,2})(?=\s|$)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled, RegexTimeout);

    private static readonly Regex HighRiskCommandLineRegex = new(
        @"(FromBase64String|Invoke-Expression|\bIEX\b|DownloadString|DownloadFile|Net\.WebClient|urlcache\s+-split|bitsadmin(\.exe)?[^\r\n]{0,256}\/transfer\s+|(Invoke-WebRequest|\biwr\b|\birm\b|Start-BitsTransfer)[^\r\n]{0,512}(Start-Process|\bIEX\b|Invoke-Expression)|curl(\.exe)?[^\r\n]{0,256}https?://[^\r\n]{0,256}\s+-[oO]\s+[^\r\n]{0,256}(Users\\Public|AppData\\Local\\Temp|\\Temp\\|ProgramData)[^\r\n]{0,128}\.(exe|dll|ps1|bat|cmd|vbs|js|hta|scr|msi)|(-w(indowstyle)?\s+hidden[^\r\n]{0,256}-e(p|xecutionpolicy)\s+bypass|-e(p|xecutionpolicy)\s+bypass[^\r\n]{0,256}-w(indowstyle)?\s+hidden)|msiexec(\.exe)?\s+[^\r\n]{0,256}https?://|regsvr32(\.exe)?\s+[^\r\n]{0,256}(/i:https?://|scrobj\.dll)|rundll32(\.exe)?\s+(javascript:|https?://)|schtasks(\.exe)?\s+/create\s+[^\r\n]{0,512}(powershell|mshta|wscript|cscript|cmd(\.exe)?\s+/c|Users\\Public|AppData\\Local\\Temp)|Add-MpPreference\s+[^\r\n]{0,256}-Exclusion|Set-MpPreference\s+[^\r\n]{0,256}-Disable(RealtimeMonitoring|BehaviorMonitoring|IOAVProtection|ScriptScanning)|wevtutil(\.exe)?\s+cl\s+(Security|System|Application|Windows\s+PowerShell)|vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|Win32_ShadowCopy[^\r\n]{0,128}Delete|wbadmin(\.exe)?\s+delete|bcdedit(\.exe)?\s+/set\s+\{default\}\s+recoveryenabled\s+no|comsvcs\.dll[^\r\n]{0,128}MiniDump|reg(\.exe)?\s+save\s+hklm\\(sam|security|system)|netsh(\.exe)?\s+advfirewall\s+set\s+[^\r\n]{0,128}state\s+off|mshta(\.exe)?\s+(https?://|javascript:|vbscript:)|wmic(\.exe)?\s+process\s+call\s+create|python(\d)?(\.exe)?\s+-c\s+[^\r\n]{0,512}((urllib|requests|http\.client)[^\r\n]{0,256}(exec\(|eval\(|subprocess)|base64[^\r\n]{0,256}(exec\(|eval\())|node(\.exe)?\s+-e\s+[^\r\n]{0,512}((http\.get|https\.get|fetch\()[^\r\n]{0,256}(child_process|eval\(|exec\()|child_process[^\r\n]{0,256}(curl|wget|powershell|cmd))|sc(\.exe)?\s+create\s+[^\r\n]{0,256}type=\s*kernel|net1?(\.exe)?\s+(user\s+[^\r\n]{0,128}\/add|localgroup\s+administrators\s+[^\r\n]{0,128}\/add)|fDenyTSConnections[^\r\n]{0,64}0)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled, RegexTimeout);

    private readonly ProcessTreeTracker? _treeTracker;
    private readonly ThreatIntelStore? _intelStore;
    private readonly CustomRuleEngine? _customRuleEngine;
    private readonly TelemetryMetrics? _metrics;

    public ProcessRuleEvaluator(
        ProcessTreeTracker? treeTracker = null,
        ThreatIntelStore? intelStore = null,
        CustomRuleEngine? customRuleEngine = null,
        TelemetryMetrics? metrics = null)
    {
        _treeTracker = treeTracker;
        _intelStore = intelStore;
        _customRuleEngine = customRuleEngine;
        _metrics = metrics;
    }

    public SecurityEvent? Evaluate(ProcessEvaluationContext ctx, GuardPolicy policy, string? originalFilenameOverride = null)
    {
        long startTs = _metrics is not null ? Stopwatch.GetTimestamp() : 0;
        try
        {
            return EvaluateCore(ctx, policy, originalFilenameOverride);
        }
        finally
        {
            if (_metrics is not null)
            {
                _metrics.RecordEvaluationTicks(Stopwatch.GetTimestamp() - startTs);
            }
        }
    }

    private SecurityEvent? EvaluateCore(ProcessEvaluationContext ctx, GuardPolicy policy, string? originalFilenameOverride)
    {
        if (!policy.EnableProcessSupplyChainGuard)
        {
            return null;
        }

        if (ctx.ProcessId <= 4 ||
            ctx.ProcessId == Environment.ProcessId ||
            InternalHelperProcessRegistry.IsInternalHelper(ctx.ProcessId, ctx.ParentProcessId) ||
            IsProtectedHostIdeProcess(ctx.ProcessPath))
        {
            return null;
        }

        _treeTracker?.RecordStart(ctx.ProcessId, ctx.ParentProcessId, ctx.ProcessName, ctx.ProcessPath, ctx.CommandLine);
        var ancestry = !string.IsNullOrWhiteSpace(ctx.AncestryChain)
            ? ctx.AncestryChain
            : (_treeTracker?.FormatAncestryString(ctx.ProcessId) ?? string.Empty);

        var childFileName = Path.GetFileName(string.IsNullOrWhiteSpace(ctx.ProcessPath)
            ? ctx.ProcessName
            : ctx.ProcessPath);
        if (!childFileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
            !string.IsNullOrWhiteSpace(childFileName))
        {
            childFileName += ".exe";
        }

        // 0. Fake Windows System Process Path Masquerading (e.g. C:\Temp\svchost.exe or C:\Users\...\lsass.exe)
        if (!string.IsNullOrWhiteSpace(ctx.ProcessPath) && SystemOnlyWindowsBinaries.Contains(childFileName))
        {
            var windowsPrefix = CachedWindowsDir.TrimEnd('\\') + "\\";
            if (windowsPrefix.Length > 1 &&
                !ctx.ProcessPath.StartsWith(windowsPrefix, StringComparison.OrdinalIgnoreCase))
            {
                return new SecurityEvent
                {
                    Severity = ThreatSeverity.Critical,
                    Category = ThreatCategory.Masquerading,
                    ActionTaken = SecurityActionTaken.Logged,
                    Title = $"시스템 핵심 프로세스 위장 실행 탐지: {childFileName}",
                    Description = $"Windows 시스템 폴더 외부 경로({ctx.ProcessPath})에서 '{childFileName}' 이름으로 위장 실행되었습니다.",
                    ProcessId = ctx.ProcessId,
                    ProcessName = ctx.ProcessName,
                    ProcessPath = ctx.ProcessPath,
                    ParentProcessId = ctx.ParentProcessId,
                    ParentProcessName = ctx.ParentProcessName,
                    ProcessAncestry = ancestry,
                    CommandLine = ctx.CommandLine,
                    TargetPath = ctx.ProcessPath,
                    RiskScore = 95,
                    RiskSignals = new List<string> { "FakeSystemProcessPath(+95)" },
                    Signature = ctx.Signature
                };
            }
        }

        // 1. Renamed LOLBin Masquerading via PE FileVersionInfo.OriginalFilename
        var originalFilename = originalFilenameOverride ?? ReadOriginalFilenameSafe(ctx.ProcessPath);
        if (!string.IsNullOrWhiteSpace(originalFilename) &&
            ProtectedLolBinOriginalNames.Contains(originalFilename) &&
            !originalFilename.Equals(childFileName, StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityEvent
            {
                Severity = ThreatSeverity.Critical,
                Category = ThreatCategory.Masquerading,
                ActionTaken = SecurityActionTaken.Logged,
                Title = $"이름 변경 위장(LOLBin Masquerading) 탐지: {originalFilename} → {childFileName}",
                Description = $"실제 원본 파일이 '{originalFilename}'인 시스템 도구를 '{childFileName}'으로 위장해 실행했습니다.",
                ProcessId = ctx.ProcessId,
                ProcessName = ctx.ProcessName,
                ProcessPath = ctx.ProcessPath,
                ParentProcessId = ctx.ParentProcessId,
                ParentProcessName = ctx.ParentProcessName,
                ProcessAncestry = ancestry,
                CommandLine = ctx.CommandLine,
                TargetPath = ctx.ProcessPath,
                RiskScore = 90,
                RiskSignals = new List<string> { $"RenamedLolBin:{originalFilename}(+90)" },
                Signature = ctx.Signature
            };
        }

        // 2. Threat Intel IOC & Global AV SHA-256 binary database check
        // Skip heavy disk hashing on trusted Microsoft system binaries to keep battery/CPU ultra-light.
        if (_intelStore is { HasBlockedHashes: true } &&
            ctx.Signature.Status != SignatureStatus.TrustedMicrosoft &&
            !string.IsNullOrWhiteSpace(ctx.ProcessPath) &&
            File.Exists(ctx.ProcessPath))
        {
            try
            {
                var fi = new FileInfo(ctx.ProcessPath);
                if (fi.Length <= 50 * 1024 * 1024)
                {
                    var sha = SignatureVerifier.ComputeSha256Cached(ctx.ProcessPath);
                    bool isUserHash = _intelStore.IsUserHashBlocked(sha);
                    bool isPublicMalwareHash = !isUserHash && !ctx.Signature.IsSigned && _intelStore.IsHashBlocked(sha) &&
                                               !(Path.GetFileName(ctx.ProcessPath).Equals("elevate.exe", StringComparison.OrdinalIgnoreCase) &&
                                                 ctx.ProcessPath.Contains(@"\Programs\", StringComparison.OrdinalIgnoreCase));
                    if (isUserHash || isPublicMalwareHash)
                    {
                        return new SecurityEvent
                        {
                            Severity = ThreatSeverity.Critical,
                            Category = ThreatCategory.StaticMalware,
                            ActionTaken = SecurityActionTaken.Logged,
                            Title = "글로벌 바이러스 DB / IOC 악성 해시 실행 탐지!",
                            Description = $"차단 목록/글로벌 악성코드 DB에 등록된 악성 파일({Path.GetFileName(ctx.ProcessPath)}, SHA-256: {sha[..16]}...)이 실행되었습니다.",
                            ProcessId = ctx.ProcessId,
                            ProcessName = ctx.ProcessName,
                            ProcessPath = ctx.ProcessPath,
                            ParentProcessId = ctx.ParentProcessId,
                            ParentProcessName = ctx.ParentProcessName,
                            ProcessAncestry = ancestry,
                            CommandLine = ctx.CommandLine,
                            TargetPath = ctx.ProcessPath,
                            RiskScore = 100,
                            RiskSignals = new List<string> { "GlobalMalwareHashMatch(+100)" },
                            Signature = ctx.Signature
                        };
                    }
                }
            }
            catch { }
        }

        // 3. Hash-aware Tamper-Evident Whitelist Check
        if (!string.IsNullOrWhiteSpace(ctx.ProcessPath))
        {
            var pinned = policy.TrustedBinaryHashes
                .FirstOrDefault(h => h.Path.Equals(ctx.ProcessPath, StringComparison.OrdinalIgnoreCase));
            if (pinned is not null && File.Exists(ctx.ProcessPath))
            {
                try
                {
                    var currentHash = SignatureVerifier.ComputeSha256Cached(ctx.ProcessPath);
                    if (currentHash.Equals(pinned.Sha256, StringComparison.OrdinalIgnoreCase))
                    {
                        return null;
                    }

                    if (!ctx.Signature.IsSigned)
                    {
                        return new SecurityEvent
                        {
                            Severity = ThreatSeverity.Critical,
                            Category = ThreatCategory.BinaryTampering,
                            ActionTaken = SecurityActionTaken.Logged,
                            Title = "신뢰 등록된 실행 파일 변조(공급망/해시 불일치) 탐지!",
                            Description = $"기존 승인된 '{Path.GetFileName(ctx.ProcessPath)}'의 SHA-256 해시가 변경되었으며 유효한 서명이 없습니다.",
                            ProcessId = ctx.ProcessId,
                            ProcessName = ctx.ProcessName,
                            ProcessPath = ctx.ProcessPath,
                            ParentProcessId = ctx.ParentProcessId,
                            ParentProcessName = ctx.ParentProcessName,
                            ProcessAncestry = ancestry,
                            CommandLine = ctx.CommandLine,
                            TargetPath = ctx.ProcessPath,
                            RiskScore = 95,
                            RiskSignals = new List<string> { "TrustedBinaryHashMismatch(+95)" },
                            Signature = ctx.Signature
                        };
                    }
                }
                catch { }
            }

            if (policy.WhitelistedExecutablePaths.Contains(ctx.ProcessPath, StringComparer.OrdinalIgnoreCase))
            {
                return null;
            }
        }

        var parentBase = Path.GetFileNameWithoutExtension(ctx.ParentProcessName);

        // 4A. HWP / Office / PDF / CHM Document Exploit Child Process Block (Kimsuky / Lazarus #1 Korean Spear-Phishing Vector!)
        if (!string.IsNullOrWhiteSpace(parentBase) && DocumentViewerParents.Contains(parentBase))
        {
            bool isDangerousChild = DangerousChildBinaries.Contains(childFileName);
            bool isUnsignedDropper = !ctx.Signature.IsSigned && IsUserWritableRiskyPath(ctx.ProcessPath);
            if (isDangerousChild || isUnsignedDropper)
            {
                return new SecurityEvent
                {
                    Severity = ThreatSeverity.Critical,
                    Category = ThreatCategory.DocumentExploit,
                    ActionTaken = SecurityActionTaken.Logged,
                    Title = $"문서/도움말({parentBase}) 취약점 악용 자식 프로세스 실행 차단!",
                    Description = $"문서 뷰어 '{ctx.ParentProcessName}'에서 비정상 하위 프로세스 '{childFileName}'이(가) 실행되었습니다 (북한 APT HWP/OLE/CHM 악성문서 수법).",
                    ProcessId = ctx.ProcessId,
                    ProcessName = ctx.ProcessName,
                    ProcessPath = ctx.ProcessPath,
                    ParentProcessId = ctx.ParentProcessId,
                    ParentProcessName = ctx.ParentProcessName,
                    ProcessAncestry = ancestry,
                    CommandLine = ctx.CommandLine,
                    TargetPath = ctx.ProcessPath,
                    RiskScore = 95,
                    RiskSignals = new List<string> { $"DocumentViewerExploitChild:{parentBase}->{childFileName}(+95)" },
                    Signature = ctx.Signature
                };
            }
        }

        // 4B. UAC Privilege Escalation Bypass via Auto-Elevating Windows Binaries (fodhelper / eventvwr / sdclt / computerdefaults)
        if (!string.IsNullOrWhiteSpace(parentBase) && UacAutoElevateParents.Contains(parentBase))
        {
            bool isShellOrUnsigned = DangerousChildBinaries.Contains(childFileName) || !ctx.Signature.IsSigned;
            if (isShellOrUnsigned)
            {
                return new SecurityEvent
                {
                    Severity = ThreatSeverity.Critical,
                    Category = ThreatCategory.PrivilegeEscalation,
                    ActionTaken = SecurityActionTaken.Logged,
                    Title = $"UAC 관리자 권한 상승 우회({parentBase}) 탐지!",
                    Description = $"자동 승격 시스템 도구 '{ctx.ParentProcessName}'를 악용해 '{childFileName}'을(를) 관리자 권한으로 우회 실행하려 했습니다.",
                    ProcessId = ctx.ProcessId,
                    ProcessName = ctx.ProcessName,
                    ProcessPath = ctx.ProcessPath,
                    ParentProcessId = ctx.ParentProcessId,
                    ParentProcessName = ctx.ParentProcessName,
                    ProcessAncestry = ancestry,
                    CommandLine = ctx.CommandLine,
                    TargetPath = ctx.ProcessPath,
                    RiskScore = 95,
                    RiskSignals = new List<string> { $"UacBypass:{parentBase}->{childFileName}(+95)" },
                    Signature = ctx.Signature
                };
            }
        }

        // 4C. Chrome/Edge App-Bound Encryption (ABE) Remote Debugging Session Hijack (2025-2026 top stealer vector!)
        bool isTrustedDebuggerParent = LegitimateDevDebuggerParents.Contains(parentBase) &&
                                       !IsHighRiskDropPath(ctx.ParentProcessPath);
        if (BrowserBinaries.Contains(childFileName) &&
            !string.IsNullOrWhiteSpace(ctx.CommandLine) &&
            (ctx.CommandLine.Contains("--remote-debugging-port", StringComparison.OrdinalIgnoreCase) ||
             ctx.CommandLine.Contains("--load-extension", StringComparison.OrdinalIgnoreCase)) &&
            !isTrustedDebuggerParent)
        {
            return new SecurityEvent
            {
                Severity = ThreatSeverity.Critical,
                Category = ThreatCategory.CredentialAccess,
                ActionTaken = SecurityActionTaken.Logged,
                Title = "브라우저 원격 디버깅(ABE 세션 쿠키 탈취 기법) 실행 탐지!",
                Description = $"비개발 상위 프로세스 '{ctx.ParentProcessName}'가 '{childFileName}'을(를) 원격 디버깅/강제확장 옵션으로 실행했습니다.",
                ProcessId = ctx.ProcessId,
                ProcessName = ctx.ProcessName,
                ProcessPath = ctx.ProcessPath,
                ParentProcessId = ctx.ParentProcessId,
                ParentProcessName = ctx.ParentProcessName,
                ProcessAncestry = ancestry,
                CommandLine = ctx.CommandLine,
                TargetPath = ctx.ProcessPath,
                RiskScore = 95,
                RiskSignals = new List<string> { "BrowserRemoteDebuggingHijack(+95)" },
                Signature = ctx.Signature
            };
        }

        // 5A. Smart Base64 -EncodedCommand real-time decoding inspection:
        // Only evaluate PowerShell -e/-ec/-enc/-EncodedCommand on actual PowerShell binaries (or cmd /c powershell ...)
        // NEVER merely because an argument path to rg.exe / docker.exe happens to contain the substring "powershell"!
        bool isPowerShellInvocation = childFileName.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase) ||
                                      childFileName.Equals("pwsh.exe", StringComparison.OrdinalIgnoreCase) ||
                                      originalFilename.StartsWith("PowerShell", StringComparison.OrdinalIgnoreCase) ||
                                      originalFilename.StartsWith("pwsh", StringComparison.OrdinalIgnoreCase) ||
                                      ((childFileName.Equals("cmd.exe", StringComparison.OrdinalIgnoreCase) ||
                                        originalFilename.Equals("cmd.exe", StringComparison.OrdinalIgnoreCase)) &&
                                       !string.IsNullOrWhiteSpace(ctx.CommandLine) &&
                                       (ctx.CommandLine.Contains("powershell", StringComparison.OrdinalIgnoreCase) ||
                                        ctx.CommandLine.Contains("pwsh", StringComparison.OrdinalIgnoreCase)));
        if (isPowerShellInvocation &&
            !string.IsNullOrWhiteSpace(ctx.CommandLine) &&
            TryDetectMaliciousEncodedCommand(ctx.CommandLine, policy, out var encodedReason, out var decodedSnippet))
        {
            return new SecurityEvent
            {
                Severity = ThreatSeverity.Critical,
                Category = ThreatCategory.FilelessScript,
                ActionTaken = SecurityActionTaken.Logged,
                Title = "Base64 인코딩(-EncodedCommand) 악성 스크립트 실행 탐지!",
                Description = $"인코딩된 명령줄 복호화 결과 위험 행위가 확인되었습니다 ({encodedReason}). 복호화 내용: {decodedSnippet}",
                ProcessId = ctx.ProcessId,
                ProcessName = ctx.ProcessName,
                ProcessPath = ctx.ProcessPath,
                ParentProcessId = ctx.ParentProcessId,
                ParentProcessName = ctx.ParentProcessName,
                ProcessAncestry = ancestry,
                CommandLine = ctx.CommandLine,
                TargetPath = ctx.ProcessPath,
                RiskScore = 95,
                RiskSignals = new List<string> { "MaliciousEncodedCommandDecoded(+95)" },
                Signature = ctx.Signature
            };
        }

        // 5B. Ransomware shadow-copy / LSASS dump / firewall disable / encoded & multi-runtime LOLBin command line
        bool isHighRiskCmd = false;
        if (!string.IsNullOrWhiteSpace(ctx.CommandLine))
        {
            try { isHighRiskCmd = HighRiskCommandLineRegex.IsMatch(ctx.CommandLine); }
            catch (RegexMatchTimeoutException) { }
        }
        if (isHighRiskCmd)
        {
            var isShadowDelete = ctx.CommandLine.Contains("vssadmin", StringComparison.OrdinalIgnoreCase) ||
                                 ctx.CommandLine.Contains("shadowcopy", StringComparison.OrdinalIgnoreCase) ||
                                 ctx.CommandLine.Contains("wbadmin", StringComparison.OrdinalIgnoreCase) ||
                                 ctx.CommandLine.Contains("recoveryenabled", StringComparison.OrdinalIgnoreCase);

            var isCredDump = ctx.CommandLine.Contains("MiniDump", StringComparison.OrdinalIgnoreCase) ||
                             ctx.CommandLine.Contains("reg save", StringComparison.OrdinalIgnoreCase);

            var isDefenseTamper = ctx.CommandLine.Contains("advfirewall", StringComparison.OrdinalIgnoreCase) ||
                                  ctx.CommandLine.Contains("MpPreference", StringComparison.OrdinalIgnoreCase) ||
                                  ctx.CommandLine.Contains("wevtutil", StringComparison.OrdinalIgnoreCase);

            var isSchedTaskPersist = ctx.CommandLine.Contains("schtasks", StringComparison.OrdinalIgnoreCase);

            var isPrivEscOrByovd = (ctx.CommandLine.Contains("sc", StringComparison.OrdinalIgnoreCase) &&
                                    ctx.CommandLine.Contains("type=", StringComparison.OrdinalIgnoreCase) &&
                                    ctx.CommandLine.Contains("kernel", StringComparison.OrdinalIgnoreCase)) ||
                                   ((ctx.CommandLine.Contains("net user", StringComparison.OrdinalIgnoreCase) ||
                                     ctx.CommandLine.Contains("net1 user", StringComparison.OrdinalIgnoreCase) ||
                                     ctx.CommandLine.Contains("localgroup", StringComparison.OrdinalIgnoreCase)) &&
                                    ctx.CommandLine.Contains("/add", StringComparison.OrdinalIgnoreCase)) ||
                                   ctx.CommandLine.Contains("fDenyTSConnections", StringComparison.OrdinalIgnoreCase);

            int score = (isShadowDelete || isCredDump || isDefenseTamper || isPrivEscOrByovd) ? 95 : 85;
            var category = isShadowDelete ? ThreatCategory.Ransomware
                : (isCredDump ? ThreatCategory.CredentialAccess
                : (isPrivEscOrByovd ? ThreatCategory.PrivilegeEscalation
                : (isDefenseTamper ? ThreatCategory.SystemIntegrityTamper
                : (isSchedTaskPersist ? ThreatCategory.Persistence : ThreatCategory.SupplyChain))));

            var title = isShadowDelete ? "랜섬웨어 복구/섀도복사본 삭제 시도 탐지!"
                : (isCredDump ? "LSASS/SAM OS 자격증명 덤프 시도 탐지!"
                : (isPrivEscOrByovd ? "커널 드라이버(BYOVD)/숨김 관리자 계정/RDP 강제 개방 시도 탐지!"
                : (isDefenseTamper ? "Defender·방화벽·보안 로그 무력화 시도 탐지!"
                : (isSchedTaskPersist ? "악성 작업 스케줄러(지속성) 실시간 등록 시도 탐지!"
                : "고위험 난독화/원격 다운로드(LOLBin) 공격 실행 탐지!"))));

            return new SecurityEvent
            {
                Severity = score >= 90 ? ThreatSeverity.Critical : ThreatSeverity.High,
                Category = category,
                ActionTaken = SecurityActionTaken.Logged,
                Title = title,
                Description = $"{ctx.ProcessName} 프로세스가 고위험 시스템 공격 명령을 실행했습니다.",
                ProcessId = ctx.ProcessId,
                ProcessName = ctx.ProcessName,
                ProcessPath = ctx.ProcessPath,
                ParentProcessId = ctx.ParentProcessId,
                ParentProcessName = ctx.ParentProcessName,
                ProcessAncestry = ancestry,
                CommandLine = ctx.CommandLine,
                TargetPath = ctx.ProcessPath,
                RiskScore = score,
                RiskSignals = new List<string> { $"HighRiskCommandLine:{category}(+{score})" },
                Signature = ctx.Signature
            };
        }

        // 5C. Detection-as-Code Custom SOC Rules (rules.json — hot-reloadable Sigma-style matchers)
        if (_customRuleEngine is not null)
        {
            var customHit = _customRuleEngine.EvaluateProcess(ctx, ancestry);
            if (customHit is not null)
            {
                _metrics?.IncrementCustomRuleHit();
                return customHit;
            }
        }

        // 6. Multi-hop Supply-chain anomaly (Direct parent OR tracked multi-level launcher ancestor)
        var launcherAncestor = _treeTracker?.FindWatchedLauncherAncestor(ctx.ProcessId, policy);
        bool fromWatchedLauncher = IsWatchedLauncherOrRenderer(parentBase, ctx.ParentProcessPath, policy) ||
                                   launcherAncestor is not null;

        if (fromWatchedLauncher)
        {
            bool isDangerousChild = DangerousChildBinaries.Contains(childFileName);
            bool isUnsignedDropper = !ctx.Signature.IsSigned && IsUserWritableRiskyPath(ctx.ProcessPath);

            if (isDangerousChild || isUnsignedDropper)
            {
                var rootName = launcherAncestor?.Name ?? ctx.ParentProcessName;
                return new SecurityEvent
                {
                    Severity = ThreatSeverity.Critical,
                    Category = ThreatCategory.SupplyChain,
                    ActionTaken = SecurityActionTaken.Logged,
                    Title = "공급망 공격 의심: 런처/웹뷰 계보에서 비정상 자식 프로세스 실행",
                    Description = $"감시 대상 런처 '{rootName}' 계보({(string.IsNullOrEmpty(ancestry) ? ctx.ParentProcessName : ancestry)})에서 위험 프로세스 '{childFileName}'이(가) 실행되었습니다.",
                    ProcessId = ctx.ProcessId,
                    ProcessName = ctx.ProcessName,
                    ProcessPath = ctx.ProcessPath,
                    ParentProcessId = ctx.ParentProcessId,
                    ParentProcessName = ctx.ParentProcessName,
                    ProcessAncestry = ancestry,
                    CommandLine = ctx.CommandLine,
                    TargetPath = ctx.ProcessPath,
                    RiskScore = 90,
                    RiskSignals = new List<string> { "LauncherSupplyChainAncestry(+90)" },
                    Signature = ctx.Signature
                };
            }
        }

        // 7. Double extension masquerading
        bool isDoubleExt = false;
        if (!string.IsNullOrWhiteSpace(ctx.ProcessPath))
        {
            try { isDoubleExt = DoubleExtensionRegex.IsMatch(ctx.ProcessPath); }
            catch (RegexMatchTimeoutException) { }
        }
        if (isDoubleExt)
        {
            return new SecurityEvent
            {
                Severity = ThreatSeverity.Critical,
                Category = ThreatCategory.UnsignedExecution,
                ActionTaken = SecurityActionTaken.Logged,
                Title = "이중 확장자 위장 실행 파일 탐지",
                Description = $"문서/이미지 파일로 위장한 실행 파일({Path.GetFileName(ctx.ProcessPath)})이 실행되었습니다.",
                ProcessId = ctx.ProcessId,
                ProcessName = ctx.ProcessName,
                ProcessPath = ctx.ProcessPath,
                ParentProcessId = ctx.ParentProcessId,
                ParentProcessName = ctx.ParentProcessName,
                ProcessAncestry = ancestry,
                CommandLine = ctx.CommandLine,
                TargetPath = ctx.ProcessPath,
                RiskScore = 90,
                RiskSignals = new List<string> { "DoubleExtensionMasquerade(+90)" },
                Signature = ctx.Signature
            };
        }

        // 8. Invalid/tampered Authenticode signature
        if (ctx.Signature.Status == SignatureStatus.InvalidOrTampered)
        {
            return new SecurityEvent
            {
                Severity = ThreatSeverity.High,
                Category = ThreatCategory.UnsignedExecution,
                ActionTaken = SecurityActionTaken.Logged,
                Title = "디지털 서명 손상/변조된 실행 파일 탐지",
                Description = $"'{ctx.ProcessName}'의 Authenticode 서명이 유효하지 않거나 변조되었습니다 ({ctx.Signature.ErrorMessage}).",
                ProcessId = ctx.ProcessId,
                ProcessName = ctx.ProcessName,
                ProcessPath = ctx.ProcessPath,
                ParentProcessId = ctx.ParentProcessId,
                ParentProcessName = ctx.ParentProcessName,
                ProcessAncestry = ancestry,
                CommandLine = ctx.CommandLine,
                TargetPath = ctx.ProcessPath,
                RiskScore = 80,
                RiskSignals = new List<string> { "InvalidAuthenticodeSignature(+80)" },
                Signature = ctx.Signature
            };
        }

        // 9. Unsigned PE static heuristic check on newly executed high-risk binaries
        if (!string.IsNullOrWhiteSpace(ctx.ProcessPath) &&
            ctx.Signature.Status == SignatureStatus.Unsigned &&
            IsHighRiskDropPath(ctx.ProcessPath))
        {
            var pe = File.Exists(ctx.ProcessPath) ? PeStaticAnalyzer.AnalyzeFile(ctx.ProcessPath) : null;
            if (pe is { IsValidPe: true, HeuristicScore: >= 65 })
            {
                return new SecurityEvent
                {
                    Severity = ThreatSeverity.Critical,
                    Category = ThreatCategory.StaticMalware,
                    ActionTaken = SecurityActionTaken.Logged,
                    Title = "패커/인젝션 의심 미서명 바이너리 실행 탐지",
                    Description = $"'{Path.GetFileName(ctx.ProcessPath)}'의 PE 정적 분석 점수가 매우 높습니다 ({pe.HeuristicScore}/100: {pe.Summary}).",
                    ProcessId = ctx.ProcessId,
                    ProcessName = ctx.ProcessName,
                    ProcessPath = ctx.ProcessPath,
                    ParentProcessId = ctx.ParentProcessId,
                    ParentProcessName = ctx.ParentProcessName,
                    ProcessAncestry = ancestry,
                    CommandLine = ctx.CommandLine,
                    TargetPath = ctx.ProcessPath,
                    RiskScore = Math.Min(95, pe.HeuristicScore + 15),
                    RiskSignals = new List<string> { $"PeStaticHeuristic:{pe.HeuristicScore}(+80)" },
                    Signature = ctx.Signature
                };
            }

            return new SecurityEvent
            {
                Severity = ThreatSeverity.Medium,
                Category = ThreatCategory.UnsignedExecution,
                ActionTaken = SecurityActionTaken.Logged,
                Title = "고위험 임시/다운로드 경로에서 미서명 실행 파일 실행 (행위 주시)",
                Description = $"디지털 서명이 없는 '{Path.GetFileName(ctx.ProcessPath)}' 파일이 위험 경로({Path.GetDirectoryName(ctx.ProcessPath)})에서 실행되었습니다. 추가 의심 행위 발생 시 자동 차단됩니다.",
                ProcessId = ctx.ProcessId,
                ProcessName = ctx.ProcessName,
                ProcessPath = ctx.ProcessPath,
                ParentProcessId = ctx.ParentProcessId,
                ParentProcessName = ctx.ParentProcessName,
                ProcessAncestry = ancestry,
                CommandLine = ctx.CommandLine,
                TargetPath = ctx.ProcessPath,
                RiskScore = 35,
                RiskSignals = new List<string> { "UnsignedHighRiskDropPath(+35)" },
                Signature = ctx.Signature
            };
        }

        return null;
    }

    public static bool TryDetectMaliciousEncodedCommand(
        string commandLine,
        GuardPolicy policy,
        out string reason,
        out string decodedPreview)
    {
        reason = string.Empty;
        decodedPreview = string.Empty;

        Match match;
        try
        {
            match = EncodedCommandExtractRegex.Match(commandLine);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
        if (!match.Success)
        {
            return false;
        }

        var b64 = match.Groups[1].Value.Trim();
        string decoded;
        try
        {
            var bytes = Convert.FromBase64String(b64);
            // PowerShell -EncodedCommand uses UTF-16LE (Unicode); fall back to UTF-8 if odd byte length or non-UTF16
            var utf16 = bytes.Length >= 2 && bytes.Length % 2 == 0
                ? System.Text.Encoding.Unicode.GetString(bytes)
                : string.Empty;
            var utf8 = System.Text.Encoding.UTF8.GetString(bytes);
            decoded = IsReadableScript(utf16) ? utf16 : (IsReadableScript(utf8) ? utf8 : string.Empty);
        }
        catch
        {
            reason = "손상되거나 비정상적인 Base64 페이로드";
            decodedPreview = b64.Length > 80 ? b64[..80] + "..." : b64;
            return true;
        }

        if (string.IsNullOrWhiteSpace(decoded))
        {
            reason = "바이너리/난독화 Base64 페이로드";
            decodedPreview = b64.Length > 80 ? b64[..80] + "..." : b64;
            return true;
        }

        decodedPreview = decoded.Length > 180 ? decoded[..180] + "..." : decoded;

        // Always inspect decoded text against both HighRiskCommandLineRegex and FilelessScriptGuard AI de-obfuscator!
        // Benign read-only status queries (e.g. Get-MpComputerStatus) naturally match zero attack rules,
        // without creating a comment-injection bypass surface.
        try
        {
            if (HighRiskCommandLineRegex.IsMatch(decoded))
            {
                reason = "복호화된 명령줄에서 고위험 공격/무력화 구문 탐지";
                return true;
            }
        }
        catch (RegexMatchTimeoutException) { }

        var scriptAlert = FilelessScriptGuard.AnalyzeScriptBlock(decoded, pid: 0, policy);
        if (scriptAlert is not null)
        {
            reason = scriptAlert.Title;
            return true;
        }

        return false;
    }

    private static bool IsReadableScript(string text)
    {
        if (text.Length < 4) return false;
        int printable = 0;
        foreach (char c in text)
        {
            // Support ASCII + all Unicode letters/digits/punctuation (Korean, Japanese, Chinese, symbols) while rejecting binary control chars
            if (c is '\r' or '\n' or '\t' || (!char.IsControl(c) && c != '\uFFFD'))
            {
                printable++;
            }
        }
        return (double)printable / text.Length >= 0.85;
    }

    private static readonly ConcurrentDictionary<string, (long LastWriteTicks, long Length, string OriginalFilename)> OriginalFilenameCache =
        new(StringComparer.OrdinalIgnoreCase);

    private static string ReadOriginalFilenameSafe(string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath)) return string.Empty;
        try
        {
            var info = new FileInfo(filePath);
            if (!info.Exists) return string.Empty;

            long ticks = info.LastWriteTimeUtc.Ticks;
            long len = info.Length;
            if (OriginalFilenameCache.TryGetValue(filePath, out var cached) &&
                cached.LastWriteTicks == ticks &&
                cached.Length == len)
            {
                return cached.OriginalFilename;
            }

            var orig = (FileVersionInfo.GetVersionInfo(filePath).OriginalFilename ?? string.Empty).Trim();
            // On localized (e.g. Korean) Windows 11, MUI redirection appends ".MUI" (e.g. "Cmd.Exe.MUI", "PowerShell.EXE.MUI")!
            if (orig.EndsWith(".MUI", StringComparison.OrdinalIgnoreCase))
            {
                orig = orig[..^4];
            }
            if (OriginalFilenameCache.Count >= 512)
            {
                OriginalFilenameCache.Clear();
            }
            OriginalFilenameCache[filePath] = (ticks, len, orig);
            return orig;
        }
        catch
        {
            return string.Empty;
        }
    }

    public static bool IsWatchedLauncherOrRenderer(string parentProcessBaseName, string parentProcessPath, GuardPolicy policy)
    {
        if (string.IsNullOrWhiteSpace(parentProcessBaseName) && string.IsNullOrWhiteSpace(parentProcessPath))
        {
            return false;
        }

        var exeBase = !string.IsNullOrWhiteSpace(parentProcessBaseName)
            ? parentProcessBaseName
            : Path.GetFileNameWithoutExtension(parentProcessPath);

        foreach (var pattern in policy.WatchedLauncherProcesses)
        {
            if (string.IsNullOrWhiteSpace(pattern)) continue;

            // Generic "launcher" token must only match the executable name itself (or *_launcher),
            // never arbitrary parent folder substrings like C:\Coding\MyLauncher\...
            if (pattern.Equals("launcher", StringComparison.OrdinalIgnoreCase))
            {
                if (exeBase.Equals("launcher", StringComparison.OrdinalIgnoreCase) ||
                    exeBase.EndsWith("_launcher", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
                continue;
            }

            if (exeBase.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string EnsureTrailingSeparator(string? dir) =>
        string.IsNullOrWhiteSpace(dir) ? string.Empty : dir.TrimEnd('\\', '/') + "\\";

    private static readonly string CachedLocalAppData = EnsureTrailingSeparator(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
    private static readonly string CachedLocalPrograms = string.IsNullOrEmpty(CachedLocalAppData) ? string.Empty : EnsureTrailingSeparator(Path.Combine(CachedLocalAppData, "Programs"));
    private static readonly string CachedAntigravityDir = string.IsNullOrEmpty(CachedLocalPrograms) ? string.Empty : EnsureTrailingSeparator(Path.Combine(CachedLocalPrograms, "antigravity"));
    private static readonly string CachedUserProfile = EnsureTrailingSeparator(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
    private static readonly string CachedDownloads = string.IsNullOrEmpty(CachedUserProfile) ? string.Empty : EnsureTrailingSeparator(Path.Combine(CachedUserProfile, "Downloads"));
    private static readonly string CachedAppData = EnsureTrailingSeparator(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
    private static readonly string CachedLocalTemp = string.IsNullOrEmpty(CachedLocalAppData) ? string.Empty : EnsureTrailingSeparator(Path.Combine(CachedLocalAppData, "Temp"));
    private static readonly string CachedWindowsDir = EnsureTrailingSeparator(Environment.GetFolderPath(Environment.SpecialFolder.Windows));
    private static readonly string CachedWindowsTemp = string.IsNullOrEmpty(CachedWindowsDir) ? string.Empty : EnsureTrailingSeparator(Path.Combine(CachedWindowsDir, "Temp"));

    public static bool IsHighRiskDropPath(string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath)) return false;

        var normalized = filePath.Contains('/') ? filePath.Replace('/', '\\') : filePath;

        // Standard per-user installed application directory (%LocalAppData%\Programs)
        // and Windows Defender's own TrustedInstaller platform folder are NOT untrusted drop paths
        if ((!string.IsNullOrEmpty(CachedLocalPrograms) &&
             normalized.StartsWith(CachedLocalPrograms, StringComparison.OrdinalIgnoreCase)) ||
            normalized.Contains(@"\ProgramData\Microsoft\Windows Defender\", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains(@"\ProgramData\chocolatey\", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains(@"\ProgramData\Package Cache\", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return (!string.IsNullOrEmpty(CachedLocalTemp) && normalized.StartsWith(CachedLocalTemp, StringComparison.OrdinalIgnoreCase)) ||
               (!string.IsNullOrEmpty(CachedWindowsTemp) && normalized.StartsWith(CachedWindowsTemp, StringComparison.OrdinalIgnoreCase)) ||
               (!string.IsNullOrEmpty(CachedDownloads) && normalized.StartsWith(CachedDownloads, StringComparison.OrdinalIgnoreCase)) ||
               (!string.IsNullOrEmpty(CachedAppData) && normalized.StartsWith(CachedAppData, StringComparison.OrdinalIgnoreCase)) ||
               normalized.Contains("\\Users\\Public\\", StringComparison.OrdinalIgnoreCase) ||
               normalized.Contains("\\ProgramData\\", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsUserWritableRiskyPath(string? filePath)
    {
        if (IsHighRiskDropPath(filePath)) return true;
        if (string.IsNullOrWhiteSpace(filePath)) return false;

        var normalized = filePath.Contains('/') ? filePath.Replace('/', '\\') : filePath;

        if (!string.IsNullOrEmpty(CachedLocalPrograms) &&
            normalized.StartsWith(CachedLocalPrograms, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return !string.IsNullOrEmpty(CachedLocalAppData) &&
               normalized.StartsWith(CachedLocalAppData, StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsProtectedHostIdeProcess(string? processPath)
    {
        if (string.IsNullOrWhiteSpace(processPath) || string.IsNullOrEmpty(CachedAntigravityDir)) return false;
        var normalized = processPath.Contains('/') ? processPath.Replace('/', '\\') : processPath;
        return normalized.StartsWith(CachedAntigravityDir, StringComparison.OrdinalIgnoreCase);
    }
}
