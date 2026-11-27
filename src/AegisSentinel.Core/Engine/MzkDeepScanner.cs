using System.Collections.Concurrent;
using System.Diagnostics;
using System.Management;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using AegisSentinel.Core.Models;
using AegisSentinel.Core.Services;

namespace AegisSentinel.Core.Engine;

/// <summary>
/// MZK (Malware Zero Kit) &amp; commercial antivirus-grade 6-stage deep malware scanner:
/// 1) Active processes (with bulk WMI CommandLine/ParentPid), Process Ghosting, &amp; unbacked RWX memory
/// 2) Persistence &amp; Autoruns (Run/Startup/IFEO/Winlogon/WMI/Tasks), Services (+ ServiceDll), &amp; Korean PUP/Grid DB
/// 3) Browser hijacking (Chrome/Edge/Whale/Brave policies, Preferences/Secure Preferences, Extensions, &amp; .lnk shortcuts)
/// 4) System &amp; network integrity (HOSTS DNS hijacking, WinInet Proxy/PAC, Defender Exclusions Paths/Processes/Extensions)
/// 5) BFS fair-coverage file system virus/YARA/PE/script/archive/macro scan (Quick / MZK Deep / Full PC / Folder / File)
/// 6) Hybrid Windows Defender global signature cross-check (latest Platform MpCmdRun.exe, multi-threat parser)
/// </summary>
public sealed class MzkDeepScanner
{
    private static readonly HashSet<string> BenignIfeoDebuggers = new(StringComparer.OrdinalIgnoreCase)
    {
        "vsjitdebugger.exe", "windbg.exe", "windbgx.exe", "procexp.exe", "procexp64.exe", "procexp64a.exe",
        "taskmgr.exe", "cdb.exe", "ntsd.exe", "x64dbg.exe"
    };

    private static readonly HashSet<string> BrowserExecutableNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome.exe", "msedge.exe", "whale.exe", "brave.exe", "firefox.exe", "opera.exe", "vivaldi.exe"
    };

    private static readonly string[] ProtectedHijackTargetDomains =
    {
        "ahnlab", "v3lite", "microsoft", "windowsupdate", "defender", "virustotal",
        "malwarebytes", "kaspersky", "bitdefender", "avast", "norton", "eset", "alyac", "estsecurity",
        "naver.com", "kakao.com", "daum.net", "google.com", "github.com", "kbstar", "shinhan", "wooribank", "hanabank", "nonghyup"
    };

    private static readonly HashSet<string> SkippedFullScanDirNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "$Recycle.Bin", "System Volume Information", "WinSxS", "Installer", "SoftwareDistribution",
        "node_modules", ".git", ".vs", "obj", "Recovery", "Config.Msi", "MSOCache", "Package Cache", "NuGet",
        "Cache_Data", "Code Cache", "GPUCache", "DawnGraphiteCache", "DawnWebGPUCache",
        "cache2", "CacheStorage", "INetCache", "ShaderCache", "D3DSCache", "CrashDumps"
    };

    private static readonly Regex SuspiciousCommandTokenRegex = new(
        @"(powershell(\.exe)?[^\r\n]{0,180}(-enc|-encodedcommand|-w\s+hidden|downloadstring|iex|invoke-expression|bypass)|mshta(\.exe)?\s+(https?://|javascript:|vbscript:)|wscript(\.exe)?[^\r\n]{0,160}\.(vbs|js|jse)|regsvr32(\.exe)?[^\r\n]{0,160}(/i:https?://|scrobj\.dll)|certutil(\.exe)?[^\r\n]{0,160}([-/]urlcache|[-/]decode)|cmd(\.exe)?\s+/c[^\r\n]{0,160}(https?://|powershell|mshta|curl))",
        RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromMilliseconds(500));

    private static readonly Regex UrlArgRegex = new(
        @"https?://[a-z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=%]+",
        RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromMilliseconds(500));

    private readonly ThreatScanner _threatScanner;
    private readonly SignatureVerifier _signatureVerifier;
    private readonly ProcessController _processController;
    private readonly PersistenceMonitor _persistenceMonitor;
    private readonly ProcessRuleEvaluator _processRuleEvaluator;
    private readonly BrowserAndPupCleaner _browserPupCleaner;

    public MzkDeepScanner(
        ThreatScanner threatScanner,
        SignatureVerifier signatureVerifier,
        ProcessController processController,
        PersistenceMonitor persistenceMonitor,
        ProcessRuleEvaluator processRuleEvaluator,
        BrowserAndPupCleaner browserPupCleaner)
    {
        _threatScanner = threatScanner;
        _signatureVerifier = signatureVerifier;
        _processController = processController;
        _persistenceMonitor = persistenceMonitor;
        _processRuleEvaluator = processRuleEvaluator;
        _browserPupCleaner = browserPupCleaner;
    }

    public Task<MzkScanResult> RunScanAsync(
        MalwareScanMode mode,
        GuardPolicy policy,
        string? customTargetPath = null,
        bool includeDefenderCrossCheck = true,
        IProgress<MzkScanProgress>? progress = null,
        CancellationToken ct = default)
    {
        return Task.Run(async () =>
        {
            var startedAt = DateTimeOffset.Now;
            var findings = new ConcurrentBag<MalwareThreatItem>();
            var summaries = new List<string>();
            int scannedItems = 0;

            bool runSystemStages = mode is MalwareScanMode.MzkDeepScan or MalwareScanMode.FullSystemScan;
            int totalStages = mode switch
            {
                MalwareScanMode.SingleFileScan => 1,
                MalwareScanMode.CustomFolderScan => 1,
                MalwareScanMode.QuickScan => 2,
                _ => includeDefenderCrossCheck ? 6 : 5
            };

            try
            {
                // Stage 1: Active Processes & Memory Injection (with bulk WMI CommandLine + Process Ghosting!)
                if (mode is MalwareScanMode.QuickScan or MalwareScanMode.MzkDeepScan or MalwareScanMode.FullSystemScan)
                {
                    ct.ThrowIfCancellationRequested();
                    progress?.Report(new MzkScanProgress(1, totalStages, "1단계: 실행 프로세스 · 명령줄 · 메모리 인젝션 검사", scannedItems, findings.Count, "실행 중 프로세스 및 명령줄 열거...", 8));
                    int before = findings.Count;
                    scannedItems += ScanActiveProcessesAndMemory(policy, findings, ct);
                    summaries.Add($"[1단계 프로세스/메모리] 탐지 {findings.Count - before}건");
                }

                // Stage 2: Persistence & Autoruns & Services (+ ServiceDll + PUP/Grid DB)
                if (runSystemStages)
                {
                    ct.ThrowIfCancellationRequested();
                    progress?.Report(new MzkScanProgress(2, totalStages, "2단계: 시작프로그램 · 레지스트리 · 서비스 · PUP 감사 (MZK)", scannedItems, findings.Count, "7대 지속성 벡터, 서비스 DLL & 국내 그리드/PUP 점검...", 20));
                    int before = findings.Count;
                    scannedItems += ScanPersistenceAndServices(policy, findings, ct);
                    summaries.Add($"[2단계 지속성/서비스/PUP] 탐지 {findings.Count - before}건");
                }

                // Stage 3: Browser Hijacking (Policies, Preferences/Secure Preferences, Extensions, & Shortcuts)
                if (runSystemStages)
                {
                    ct.ThrowIfCancellationRequested();
                    progress?.Report(new MzkScanProgress(3, totalStages, "3단계: 브라우저 하이재킹 · 확장프로그램 · 바로가기 검사", scannedItems, findings.Count, "Chrome/Edge/Whale/Brave 정책·프로필·확장 검사...", 32));
                    int before = findings.Count;
                    scannedItems += ScanBrowserHijacks(findings, ct);
                    summaries.Add($"[3단계 브라우저 하이재킹] 탐지 {findings.Count - before}건");
                }

                // Stage 4: System & Network Integrity (HOSTS, Proxy/PAC, Defender Exclusions)
                if (runSystemStages)
                {
                    ct.ThrowIfCancellationRequested();
                    progress?.Report(new MzkScanProgress(4, totalStages, "4단계: HOSTS · 프록시 · Defender 예외 변조 검사", scannedItems, findings.Count, "시스템 네트워크 및 보안 설정 검증...", 42));
                    int before = findings.Count;
                    scannedItems += ScanSystemAndNetworkIntegrity(findings, ct);
                    summaries.Add($"[4단계 시스템/네트워크] 탐지 {findings.Count - before}건");
                }

                // Stage 5: Fair BFS Disk Virus / YARA / PE / Script / Macro / Archive Scan
                ct.ThrowIfCancellationRequested();
                int fileStageIdx = runSystemStages ? 5 : (mode == MalwareScanMode.QuickScan ? 2 : 1);
                string fileStageName = mode switch
                {
                    MalwareScanMode.FullSystemScan => $"{fileStageIdx}단계: 전체 PC 디스크 정밀 바이러스 검사",
                    MalwareScanMode.MzkDeepScan => $"{fileStageIdx}단계: MZK 광역 고위험 영역(Local/Roaming/Temp/Downloads/ProgramData/Program Files) 정밀 검사",
                    MalwareScanMode.CustomFolderScan => "지정 폴더 정밀 바이러스 검사",
                    MalwareScanMode.SingleFileScan => "단일 파일 정밀 바이러스 검사",
                    _ => "2단계: 빠른 파일·스크립트·시그니처 검사"
                };

                int beforeFiles = findings.Count;
                int baseScanned = scannedItems;
                var (filesScanned, truncatedRoots) = ScanFilesForMode(mode, policy, customTargetPath, findings,
                    (fileScanned, currentFile, pct) =>
                    {
                        double overallPct = runSystemStages
                            ? 44.0 + (pct * (includeDefenderCrossCheck ? 0.44 : 0.56))
                            : (mode == MalwareScanMode.QuickScan ? 20.0 + (pct * 0.80) : pct);
                        progress?.Report(new MzkScanProgress(fileStageIdx, totalStages, fileStageName, baseScanned + fileScanned, findings.Count, currentFile, Math.Min(99.0, overallPct)));
                    }, ct);
                scannedItems += filesScanned;
                var truncNote = truncatedRoots > 0 ? $" (상한 도달 폴더 {truncatedRoots}곳)" : string.Empty;
                summaries.Add($"[파일/시그니처 검사] {filesScanned:N0}건 검사 · 탐지 {findings.Count - beforeFiles}건{truncNote}");

                // Stage 6: Hybrid Windows Defender Signature Cross-Check
                if (runSystemStages && includeDefenderCrossCheck && !ct.IsCancellationRequested)
                {
                    progress?.Report(new MzkScanProgress(6, totalStages, "6단계: Windows Defender 글로벌 시그니처 교차 검증", scannedItems, findings.Count, "최신 Defender 플랫폼 엔진(MpCmdRun) 교차 검증 중...", 90));
                    int beforeDef = findings.Count;
                    var (defChecked, defTimeouts) = await RunDefenderCrossCheckAsync(findings, ct);
                    scannedItems += defChecked;
                    var defNote = defTimeouts > 0 ? $" (시간초과 {defTimeouts}곳)" : string.Empty;
                    summaries.Add($"[6단계 Defender 교차검증] {defChecked}개 영역 · 탐지 {findings.Count - beforeDef}건{defNote}");
                }

                var deduped = DeduplicateAndOrder(findings);
                progress?.Report(new MzkScanProgress(totalStages, totalStages, "검사 완료", scannedItems, deduped.Count, "모든 검사 단계가 완료되었습니다.", 100));
                return new MzkScanResult(mode, startedAt, DateTimeOffset.Now, scannedItems, false, deduped, summaries);
            }
            catch (OperationCanceledException)
            {
                var partial = DeduplicateAndOrder(findings);
                summaries.Add("[사용자 요청으로 검사 중지됨]");
                progress?.Report(new MzkScanProgress(totalStages, totalStages, "검사 중지됨", scannedItems, partial.Count, "사용자가 검사를 중지했습니다.", 100));
                return new MzkScanResult(mode, startedAt, DateTimeOffset.Now, scannedItems, true, partial, summaries);
            }
        }, ct);
    }

    private int ScanActiveProcessesAndMemory(GuardPolicy policy, ConcurrentBag<MalwareThreatItem> findings, CancellationToken ct)
    {
        int scanned = 0;
        var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenSideloadHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";
        var wmiMeta = FetchProcessMetadataBulk();

        var procs = Process.GetProcesses();
        try
        {
            foreach (var proc in procs)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    if (proc.Id <= 4 || proc.Id == Environment.ProcessId) continue;
                    try { if (proc.HasExited) continue; } catch { }
                    _processController.TryGetProcessInstanceIdentity(proc.Id, out var procIdentity);
                    var path = !string.IsNullOrWhiteSpace(procIdentity?.ExecutablePath)
                        ? procIdentity.ExecutablePath
                        : _processController.GetExecutablePath(proc.Id);
                    if (string.IsNullOrWhiteSpace(path)) continue;
                    if (ProcessRuleEvaluator.IsProtectedHostIdeProcess(path)) continue;

                    long creationTimeUtc = procIdentity?.CreationTimeFileTimeUtc ?? 0;
                    if (creationTimeUtc == 0)
                    {
                        try { creationTimeUtc = proc.StartTime.ToUniversalTime().ToFileTimeUtc(); } catch { }
                    }

                    scanned++;
                    bool fileExists = File.Exists(path);
                    wmiMeta.TryGetValue(proc.Id, out var meta);

                    // Fix Process Ghosting dead code: if the running executable was deleted from disk, verify live handle!
                    if (!fileExists)
                    {
                        var ghostRes = MemoryInspectionGuard.InspectProcessMemory(proc.Id, proc.ProcessName, path, requireLiveProcessHandle: true);
                        if (ghostRes.IsSuspicious)
                        {
                            findings.Add(new MalwareThreatItem
                            {
                                Stage = MalwareScanStage.ActiveProcessAndMemory,
                                ThreatName = "Trojan.Win32.ProcessGhosting",
                                CategoryLabel = "Process Ghosting (디스크 삭제 실행)",
                                Severity = ThreatSeverity.Critical,
                                RiskScore = 95,
                                TargetPath = path,
                                ProcessId = proc.Id,
                                ProcessCreationTimeFileTimeUtc = creationTimeUtc,
                                HostProcessPath = path,
                                TargetFileExistedAtScan = false,
                                SignatureLabel = "디스크 원본 삭제됨",
                                Description = $"실행 파일이 디스크에서 삭제된 채 메모리에서 실행 중입니다 (PID {proc.Id}, {path})",
                                ActionType = RemediationActionType.TerminateAndQuarantine,
                                RecommendedForCure = true
                            });
                        }
                        continue;
                    }

                    var sig = _signatureVerifier.VerifyFile(path);

                    // 1A. Process masquerading / renamed LOLBin / full CommandLine & ParentPid evaluation
                    var eval = _processRuleEvaluator.Evaluate(new ProcessEvaluationContext
                    {
                        ProcessId = proc.Id,
                        ProcessName = proc.ProcessName,
                        ProcessPath = path,
                        ParentProcessId = meta.ParentPid,
                        CommandLine = meta.CommandLine ?? string.Empty,
                        Signature = sig
                    }, policy);

                    if (eval is not null && eval.RiskScore >= 75)
                    {
                        findings.Add(new MalwareThreatItem
                        {
                            Stage = MalwareScanStage.ActiveProcessAndMemory,
                            ThreatName = $"Trojan.Win32.{eval.Category}",
                            CategoryLabel = "실행 프로세스 위협",
                            Severity = eval.Severity,
                            RiskScore = eval.RiskScore,
                            TargetPath = path,
                            ProcessId = proc.Id,
                            ProcessCreationTimeFileTimeUtc = creationTimeUtc,
                            HostProcessPath = path,
                            TargetFileExistedAtScan = true,
                            Sha256 = ComputeFileSha256Safe(path),
                            SignatureLabel = sig.DisplayLabel,
                            Description = $"{eval.Title} — {eval.Description}",
                            ActionType = QuarantineManager.IsProtectedSystemOrSelfPath(path)
                                ? RemediationActionType.ManualReview
                                : RemediationActionType.TerminateAndQuarantine,
                            RecommendedForCure = !QuarantineManager.IsProtectedSystemOrSelfPath(path)
                        });
                    }

                    // 1B. Static scan of running executable (skip only trusted Microsoft inbox binaries; NEVER skip Windows\Temp or Windows\Tasks!)
                    bool isTrustedWindowsInbox = sig.Status == SignatureStatus.TrustedMicrosoft &&
                                                 path.StartsWith(windowsDir, StringComparison.OrdinalIgnoreCase) &&
                                                 !path.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) &&
                                                 !path.Contains(@"\Tasks\", StringComparison.OrdinalIgnoreCase) &&
                                                 !path.Contains(@"\Debug\", StringComparison.OrdinalIgnoreCase);

                    if (!isTrustedWindowsInbox && seenPaths.Add(path))
                    {
                        var fileFinding = _threatScanner.ScanFile(path, policy, includeClean: false);
                        if (fileFinding is not null && fileFinding.RiskScore >= 55)
                        {
                            findings.Add(ConvertScanFindingToThreatItem(
                                fileFinding,
                                MalwareScanStage.ActiveProcessAndMemory,
                                proc.Id,
                                creationTimeUtc,
                                path));
                        }
                    }

                    // 1C. Live DLL Sideloading check on signed running processes (deduplicated per host binary!)
                    if (sig.IsSigned && !isTrustedWindowsInbox && seenSideloadHosts.Add(path))
                    {
                        foreach (var sideloadHit in DllSideloadingDetector.InspectRunningProcessModules(
                            proc,
                            path,
                            sig,
                            _signatureVerifier,
                            ct,
                            hostCreationTimeFileTimeUtc: creationTimeUtc))
                        {
                            findings.Add(sideloadHit);
                        }
                    }

                    // 1D. Memory injection inspection on unsigned binaries in user-writable drop paths
                    if (!sig.IsSigned && ProcessRuleEvaluator.IsUserWritableRiskyPath(path))
                    {
                        var memRes = MemoryInspectionGuard.InspectProcessMemory(proc.Id, proc.ProcessName, path, requireLiveProcessHandle: true);
                        if (memRes.IsSuspicious)
                        {
                            findings.Add(new MalwareThreatItem
                            {
                                Stage = MalwareScanStage.ActiveProcessAndMemory,
                                ThreatName = memRes.IsGhostDeletedOnDisk ? "Trojan.Win32.ProcessGhosting" : "Trojan.Win32.MemoryInjection",
                                CategoryLabel = "메모리 인젝션",
                                Severity = ThreatSeverity.Critical,
                                RiskScore = 92,
                                TargetPath = path,
                                ProcessId = proc.Id,
                                ProcessCreationTimeFileTimeUtc = creationTimeUtc,
                                HostProcessPath = path,
                                TargetFileExistedAtScan = !memRes.IsGhostDeletedOnDisk && File.Exists(path),
                                Sha256 = memRes.IsGhostDeletedOnDisk ? string.Empty : ComputeFileSha256Safe(path),
                                SignatureLabel = sig.DisplayLabel,
                                Description = $"비정상 Unbacked 실행 메모리 감지 (RWX={memRes.UnbackedRwxRegionCount}개, RX={memRes.UnbackedRxRegionCount}개, PID {proc.Id})",
                                ActionType = RemediationActionType.TerminateAndQuarantine,
                                RecommendedForCure = true
                            });
                        }
                    }
                }
                catch { }
            }
        }
        finally
        {
            foreach (var proc in procs)
            {
                try { proc.Dispose(); } catch { }
            }
        }

        return scanned;
    }

    private static Dictionary<int, (int ParentPid, string CommandLine)> FetchProcessMetadataBulk()
    {
        var map = new Dictionary<int, (int, string)>();
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT ProcessId, ParentProcessId, CommandLine FROM Win32_Process");
            using var results = searcher.Get();
            foreach (ManagementBaseObject obj in results)
            using (obj)
            {
                int pid = Convert.ToInt32(obj["ProcessId"] ?? 0);
                int ppid = Convert.ToInt32(obj["ParentProcessId"] ?? 0);
                string cmd = obj["CommandLine"]?.ToString() ?? string.Empty;
                if (pid > 4) map[pid] = (ppid, cmd);
            }
        }
        catch { }
        return map;
    }

    private int ScanPersistenceAndServices(GuardPolicy policy, ConcurrentBag<MalwareThreatItem> findings, CancellationToken ct)
    {
        int scanned = 0;
        var inventory = _persistenceMonitor.GetFullPersistenceInventory();
        var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";

        foreach (var entry in inventory)
        {
            ct.ThrowIfCancellationRequested();
            scanned++;

            if (entry.Name.Equals("AegisSentinelGuard", StringComparison.OrdinalIgnoreCase) ||
                entry.Name.Equals("AegisSentinelGuardElevated", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var exe = entry.ExtractedExecutablePath;
            if (!string.IsNullOrWhiteSpace(exe) &&
                policy.WhitelistedExecutablePaths.Any(w => w.Equals(exe, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            var entrySigLabel = entry.Signature?.DisplayLabel ?? "알 수 없음";
            bool entryIsSigned = entry.Signature?.IsSigned == true;

            // 2A. IFEO Debugger Hijack (require BOTH known debugger name AND valid signature or trusted System32/Program Files path!)
            if (entry.Category.Equals("IFEO-Debugger", StringComparison.OrdinalIgnoreCase))
            {
                var dbgFile = Path.GetFileName(exe);
                bool isTrustedBenignDebugger = BenignIfeoDebuggers.Contains(dbgFile) &&
                                               (entryIsSigned ||
                                                exe.StartsWith(windowsDir + "System32\\", StringComparison.OrdinalIgnoreCase));
                if (!isTrustedBenignDebugger)
                {
                    var ifeoAssoc = File.Exists(exe) && !QuarantineManager.IsProtectedSystemOrSelfPath(exe) ? exe : null;
                    findings.Add(new MalwareThreatItem
                    {
                        Stage = MalwareScanStage.PersistenceAndService,
                        ThreatName = "Hijacker.Win32.IFEODebugger",
                        CategoryLabel = "IFEO 디버거 하이재킹",
                        Severity = ThreatSeverity.Critical,
                        RiskScore = 95,
                        TargetPath = entry.SourceLocation,
                        EntryName = entry.Name,
                        AssociatedFilePath = ifeoAssoc,
                        AssociatedFileSha256 = ifeoAssoc is not null ? ComputeFileSha256Safe(ifeoAssoc) : null,
                        SignatureLabel = entrySigLabel,
                        Description = $"정상 프로그램 실행을 가로채는 IFEO Debugger 등록 감지: {entry.Name} → {entry.Value}",
                        ActionType = RemediationActionType.RollbackRegistryOrStartup,
                        RecommendedForCure = true
                    });
                }
                continue;
            }

            // 2B. Winlogon Shell / Userinit Tampering
            if (entry.Category.Equals("Winlogon", StringComparison.OrdinalIgnoreCase))
            {
                var val = entry.Value.Trim();
                bool isTamperedShell = entry.Name.Equals("Shell", StringComparison.OrdinalIgnoreCase) &&
                                       !val.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase);
                var expectedUserinit = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "userinit.exe");
                var cleanUserinit = val.TrimEnd(',').Trim();
                bool isTamperedUserinit = entry.Name.Equals("Userinit", StringComparison.OrdinalIgnoreCase) &&
                                          !cleanUserinit.Equals(expectedUserinit, StringComparison.OrdinalIgnoreCase) &&
                                          !cleanUserinit.Equals("userinit.exe", StringComparison.OrdinalIgnoreCase);
                if (isTamperedShell || isTamperedUserinit)
                {
                    findings.Add(new MalwareThreatItem
                    {
                        Stage = MalwareScanStage.PersistenceAndService,
                        ThreatName = "Backdoor.Win32.WinlogonHijack",
                        CategoryLabel = "Winlogon 변조",
                        Severity = ThreatSeverity.Critical,
                        RiskScore = 98,
                        TargetPath = entry.SourceLocation,
                        EntryName = entry.Name,
                        SignatureLabel = entrySigLabel,
                        Description = $"Windows 로그인 핵심 키({entry.Name})가 비정상 값으로 변조됨: {val} (안전 기본값 복구 가능)",
                        ActionType = RemediationActionType.RollbackRegistryOrStartup,
                        RecommendedForCure = true
                    });
                }
                continue;
            }

            // 2C. WMI CommandLineEventConsumer (Fileless persistence)
            if (entry.Category.Equals("WMI-Subscription", StringComparison.OrdinalIgnoreCase))
            {
                var wmiAssoc = File.Exists(exe) && !QuarantineManager.IsProtectedSystemOrSelfPath(exe) ? exe : null;
                findings.Add(new MalwareThreatItem
                {
                    Stage = MalwareScanStage.PersistenceAndService,
                    ThreatName = "Backdoor.WMI.EventConsumer",
                    CategoryLabel = "WMI 파일리스 지속성",
                    Severity = ThreatSeverity.Critical,
                    RiskScore = 90,
                    TargetPath = entry.SourceLocation,
                    EntryName = entry.Name,
                    AssociatedFilePath = wmiAssoc,
                    AssociatedFileSha256 = wmiAssoc is not null ? ComputeFileSha256Safe(wmiAssoc) : null,
                    SignatureLabel = entrySigLabel,
                    Description = $"WMI 영구 이벤트 소비자 감지: {entry.Name} → {entry.Value}",
                    ActionType = RemediationActionType.ManualReview,
                    RecommendedForCure = false
                });
                continue;
            }

            // 2D. Run / RunOnce / Startup / Scheduled-Task (fixed category prefix check + scan even signed files against IOC hash DB!)
            bool hasSuspiciousCmd = SuspiciousCommandTokenRegex.IsMatch(entry.Value);
            bool isShortcutInStartup = entry.Category.StartsWith("Startup", StringComparison.OrdinalIgnoreCase) &&
                                       exe.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase);
            bool isUnsignedRiskyDrop = !entryIsSigned &&
                                       !isShortcutInStartup &&
                                       !string.IsNullOrWhiteSpace(exe) &&
                                       File.Exists(exe) &&
                                       ProcessRuleEvaluator.IsHighRiskDropPath(exe);
            bool isMaliciousFile = false;
            if (!string.IsNullOrWhiteSpace(exe) && File.Exists(exe) &&
                entry.Signature?.Status != SignatureStatus.TrustedMicrosoft)
            {
                var scan = _threatScanner.ScanFile(exe, policy, includeClean: false);
                isMaliciousFile = scan is { RiskScore: >= 65 };
            }

            bool isRunStartupOrTask =
                entry.Category.StartsWith("Run", StringComparison.OrdinalIgnoreCase) ||
                entry.Category.StartsWith("Startup", StringComparison.OrdinalIgnoreCase) ||
                entry.Category.Equals("Scheduled-Task", StringComparison.OrdinalIgnoreCase);

            if (hasSuspiciousCmd || isMaliciousFile || (isUnsignedRiskyDrop && isRunStartupOrTask))
            {
                bool isTask = entry.Category.Equals("Scheduled-Task", StringComparison.OrdinalIgnoreCase);
                var runAssoc = File.Exists(exe) && !QuarantineManager.IsProtectedSystemOrSelfPath(exe) ? exe : null;
                findings.Add(new MalwareThreatItem
                {
                    Stage = MalwareScanStage.PersistenceAndService,
                    ThreatName = hasSuspiciousCmd ? "Trojan.Persistence.MaliciousCommand" : "PUA.Persistence.UnsignedAutoStart",
                    CategoryLabel = isTask ? "의심 예약 작업" : "악성 자동실행 등록",
                    Severity = (hasSuspiciousCmd || isMaliciousFile) ? ThreatSeverity.Critical : ThreatSeverity.High,
                    RiskScore = (hasSuspiciousCmd || isMaliciousFile) ? 90 : 75,
                    TargetPath = entry.SourceLocation,
                    EntryName = entry.Name,
                    AssociatedFilePath = runAssoc,
                    AssociatedFileSha256 = runAssoc is not null ? ComputeFileSha256Safe(runAssoc) : null,
                    SignatureLabel = entrySigLabel,
                    Description = $"[{entry.Category}] {entry.Name} → {entry.Value}",
                    ActionType = isTask ? RemediationActionType.DeleteScheduledTask : RemediationActionType.RollbackRegistryOrStartup,
                    RecommendedForCure = hasSuspiciousCmd || isMaliciousFile
                });
            }
        }

        // 2E. Inspect Windows Services (+ Parameters\ServiceDll + expanded NT paths + binary scanning)
        scanned += ScanSuspiciousServices(policy, findings, ct);

        // 2F. Declarative Korean Grid Delivery / Adware (PUP) uninstall & service rules
        foreach (var pup in _browserPupCleaner.ScanInstalledPups(ct))
        {
            findings.Add(pup);
            scanned++;
        }
        return scanned;
    }

    private int ScanSuspiciousServices(GuardPolicy policy, ConcurrentBag<MalwareThreatItem> findings, CancellationToken ct)
    {
        int count = 0;
        try
        {
            using var servicesRoot = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (servicesRoot is null) return 0;

            foreach (var svcName in servicesRoot.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                count++;
                try
                {
                    using var svcKey = servicesRoot.OpenSubKey(svcName);
                    if (svcKey is null) continue;
                    if (svcKey.GetValue("Start") is int st && st == 4) continue;

                    var rawImagePath = svcKey.GetValue("ImagePath")?.ToString() ?? string.Empty;
                    var serviceDll = string.Empty;
                    try
                    {
                        using var paramKey = svcKey.OpenSubKey("Parameters");
                        serviceDll = paramKey?.GetValue("ServiceDll")?.ToString() ?? string.Empty;
                    }
                    catch { }

                    var expanded = NormalizeNtPath(Environment.ExpandEnvironmentVariables(rawImagePath));
                    var expandedDll = NormalizeNtPath(Environment.ExpandEnvironmentVariables(serviceDll));

                    bool badCmd = SuspiciousCommandTokenRegex.IsMatch(expanded);
                    var targetBin = !string.IsNullOrWhiteSpace(expandedDll)
                        ? PersistenceMonitor.ExtractExecutablePath(expandedDll)
                        : PersistenceMonitor.ExtractExecutablePath(expanded);

                    bool inRiskyDrop = !string.IsNullOrWhiteSpace(targetBin) &&
                                       (ProcessRuleEvaluator.IsHighRiskDropPath(targetBin) ||
                                        targetBin.Contains(@"\AppData\", StringComparison.OrdinalIgnoreCase));

                    if (!badCmd && !inRiskyDrop) continue;

                    var sig = File.Exists(targetBin)
                        ? _signatureVerifier.VerifyFile(targetBin)
                        : new SignatureInfo(SignatureStatus.Unknown, string.Empty);
                    if (sig.Status == SignatureStatus.TrustedMicrosoft) continue;

                    bool staticMalicious = File.Exists(targetBin) &&
                                           _threatScanner.ScanFile(targetBin, policy, includeClean: false) is { RiskScore: >= 65 };
                    if (!badCmd && !staticMalicious && sig.IsSigned) continue;

                    bool fileExists = !string.IsNullOrWhiteSpace(targetBin) && File.Exists(targetBin);
                    bool isDemandOrManual = svcKey.GetValue("Start") is int startVal && startVal == 3;
                    bool isConfirmedThreat = badCmd || staticMalicious;
                    var svcAssoc = fileExists && !QuarantineManager.IsProtectedSystemOrSelfPath(targetBin) ? targetBin : null;
                    findings.Add(new MalwareThreatItem
                    {
                        Stage = MalwareScanStage.PersistenceAndService,
                        ThreatName = badCmd ? "Backdoor.Service.MaliciousCommand" : "Trojan.Service.SuspiciousDropPath",
                        CategoryLabel = !string.IsNullOrWhiteSpace(expandedDll) ? "의심 서비스 DLL" : "의심 Windows 서비스",
                        Severity = isConfirmedThreat || (fileExists && !isDemandOrManual) ? ThreatSeverity.Critical : ThreatSeverity.Medium,
                        RiskScore = isConfirmedThreat ? 95 : (fileExists && !isDemandOrManual ? 85 : 55),
                        TargetPath = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                        EntryName = svcName,
                        AssociatedFilePath = svcAssoc,
                        AssociatedFileSha256 = svcAssoc is not null ? ComputeFileSha256Safe(svcAssoc) : null,
                        SignatureLabel = sig.DisplayLabel,
                        Description = $"고위험 경로/명령줄을 사용하는 서비스 감지: {svcName} ({(!string.IsNullOrWhiteSpace(expandedDll) ? expandedDll : expanded)}){(!fileExists ? " [현재 디스크에 파일 없음 — 수동 확인 권장]" : string.Empty)}",
                        ActionType = RemediationActionType.DisableMaliciousService,
                        RecommendedForCure = isConfirmedThreat || (fileExists && !isDemandOrManual)
                    });
                }
                catch { }
            }
        }
        catch { }

        return count;
    }

    private static string NormalizeNtPath(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return string.Empty;
        var s = raw.Trim();
        if (s.StartsWith(@"\??\", StringComparison.Ordinal)) s = s[4..];
        if (s.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\');
            s = win + "\\" + s[@"\SystemRoot\".Length..];
        }
        return s;
    }

    private int ScanBrowserHijacks(ConcurrentBag<MalwareThreatItem> findings, CancellationToken ct)
    {
        int scanned = 0;

        // 3A. Registry browser policies (ExtensionInstallForcelist + HomepageLocation + RestoreOnStartupURLs + DefaultSearchProviderSearchURL)
        var browserPolicyBases = new (RegistryKey Hive, string HiveLabel, string BaseSubKey, string Browser)[]
        {
            (Registry.LocalMachine, "HKLM", @"SOFTWARE\Policies\Google\Chrome", "Chrome"),
            (Registry.CurrentUser,  "HKCU", @"SOFTWARE\Policies\Google\Chrome", "Chrome"),
            (Registry.LocalMachine, "HKLM", @"SOFTWARE\Policies\Microsoft\Edge", "Edge"),
            (Registry.CurrentUser,  "HKCU", @"SOFTWARE\Policies\Microsoft\Edge", "Edge"),
            (Registry.LocalMachine, "HKLM", @"SOFTWARE\Policies\Naver\Naver Whale", "Whale"),
            (Registry.CurrentUser,  "HKCU", @"SOFTWARE\Policies\Naver\Naver Whale", "Whale"),
            (Registry.LocalMachine, "HKLM", @"SOFTWARE\Policies\BraveSoftware\Brave", "Brave"),
            (Registry.CurrentUser,  "HKCU", @"SOFTWARE\Policies\BraveSoftware\Brave", "Brave")
        };

        foreach (var (hive, hiveLabel, baseSubKey, browser) in browserPolicyBases)
        {
            ct.ThrowIfCancellationRequested();
            scanned++;
            try
            {
                // Forced extensions subkey (split literals so AegisSentinel.Core.dll never self-matches YARA rules!)
                var forceSub = $@"{baseSubKey}\{string.Concat("ExtensionInstall", "Forcelist")}";
                using (var key = hive.OpenSubKey(forceSub))
                {
                    if (key is not null)
                    {
                        foreach (var valueName in key.GetValueNames())
                        {
                            var val = key.GetValue(valueName)?.ToString() ?? string.Empty;
                            if (string.IsNullOrWhiteSpace(val)) continue;
                            findings.Add(new MalwareThreatItem
                            {
                                Stage = MalwareScanStage.BrowserHijack,
                                ThreatName = $"Hijacker.Browser.{browser}ForcedExtension",
                                CategoryLabel = "브라우저 강제 확장프로그램",
                                Severity = ThreatSeverity.High,
                                RiskScore = 82,
                                TargetPath = $@"{hiveLabel}\{forceSub}",
                                EntryName = valueName,
                                SignatureLabel = "브라우저 정책 레지스트리",
                                Description = $"{browser} 강제 설치 확장프로그램 정책이 등록되어 있습니다(애드웨어/하이재커 주요 수법): {valueName} = {val}",
                                ActionType = RemediationActionType.CleanBrowserPolicy,
                                RecommendedForCure = true
                            });
                        }
                    }
                }

                // Forced Homepage / NewTab / Search URL values
                using (var baseKey = hive.OpenSubKey(baseSubKey))
                {
                    if (baseKey is not null)
                    {
                        var policyUrlValues = new[]
                        {
                            string.Concat("Homepage", "Location"),
                            string.Concat("NewTabPage", "Location"),
                            string.Concat("DefaultSearchProvider", "SearchURL")
                        };
                        foreach (var valName in policyUrlValues)
                        {
                            var val = baseKey.GetValue(valName)?.ToString()?.Trim();
                            if (!string.IsNullOrWhiteSpace(val) && !IsTrustedOfficialBrowserUrl(val))
                            {
                                findings.Add(new MalwareThreatItem
                                {
                                    Stage = MalwareScanStage.BrowserHijack,
                                    ThreatName = $"Hijacker.Browser.{browser}PolicyUrl",
                                    CategoryLabel = "브라우저 정책 URL 변조",
                                    Severity = ThreatSeverity.High,
                                    RiskScore = 80,
                                    TargetPath = $@"{hiveLabel}\{baseSubKey}",
                                    EntryName = valName,
                                    SignatureLabel = "브라우저 정책 레지스트리",
                                    Description = $"{browser} 정책({valName})에 외부 강제 URL이 등록되어 있습니다: {val}",
                                    ActionType = RemediationActionType.CleanBrowserPolicy,
                                    RecommendedForCure = true
                                });
                            }
                        }
                    }
                }
            }
            catch { }
        }

        // 3B. Hijacked browser shortcuts (.lnk) on Desktop / Start Menu (recursive!) / Taskbar
        var shortcutDirs = new (string Path, bool Recursive)[]
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), false),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory), false),
            (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"), false),
            (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Microsoft\Windows\Start Menu\Programs"), true),
            (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows\Start Menu\Programs"), true)
        };

        foreach (var (dir, recursive) in shortcutDirs)
        {
            if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir)) continue;
            try
            {
                var opts = new System.IO.EnumerationOptions
                {
                    RecurseSubdirectories = recursive,
                    MaxRecursionDepth = recursive ? 4 : 0,
                    IgnoreInaccessible = true,
                    AttributesToSkip = FileAttributes.ReparsePoint
                };
                foreach (var lnkPath in Directory.EnumerateFiles(dir, "*.lnk", opts))
                {
                    ct.ThrowIfCancellationRequested();
                    scanned++;
                    var hijack = InspectBrowserShortcutHijack(lnkPath);
                    if (hijack is not null)
                    {
                        findings.Add(hijack);
                    }
                }
            }
            catch { }
        }

        // 3C. Deep Chrome / Edge / Whale / Brave Preferences + Secure Preferences & Extension Manifest audit
        foreach (var profFinding in _browserPupCleaner.ScanBrowserProfiles(ct))
        {
            findings.Add(profFinding);
            scanned++;
        }

        return scanned;
    }

    public static MalwareThreatItem? InspectBrowserShortcutHijack(string lnkPath)
    {
        try
        {
            if (!File.Exists(lnkPath)) return null;
            var raw = File.ReadAllBytes(lnkPath);
            if (raw.Length < 76 || raw[0] != 0x4C || raw[1] != 0x00) return null;

            // Decode ASCII + BOTH even-aligned AND odd-aligned UTF-16LE (fixes 50% odd-offset LNK StringData miss!)
            var sb = new StringBuilder(raw.Length * 2);
            sb.Append(Encoding.ASCII.GetString(raw));
            sb.Append('\n');
            sb.Append(Encoding.Unicode.GetString(raw));
            if (raw.Length > 1)
            {
                sb.Append('\n');
                sb.Append(Encoding.Unicode.GetString(raw, 1, raw.Length - 1));
            }
            var combined = sb.ToString();

            bool targetsBrowser = BrowserExecutableNames.Any(b => combined.Contains(b, StringComparison.OrdinalIgnoreCase));
            if (!targetsBrowser) return null;

            bool hasDangerousFlag = combined.Contains("--load-extension", StringComparison.OrdinalIgnoreCase) ||
                                    combined.Contains("--remote-debugging-port", StringComparison.OrdinalIgnoreCase) ||
                                    combined.Contains("--proxy-server", StringComparison.OrdinalIgnoreCase);

            // Legitimate Chrome/Edge PWA shortcuts use --app-id= or --app= (skip URL check unless dangerous flags are present)
            bool isLegitimatePwaShortcut =
                !hasDangerousFlag &&
                (lnkPath.Contains(@"\Chrome Apps\", StringComparison.OrdinalIgnoreCase) ||
                 combined.Contains("--app-id=", StringComparison.OrdinalIgnoreCase) ||
                 combined.Contains("--app=", StringComparison.OrdinalIgnoreCase));

            string? badUrl = null;
            if (!isLegitimatePwaShortcut)
            {
                foreach (Match m in UrlArgRegex.Matches(combined))
                {
                    if (!IsTrustedOfficialBrowserUrl(m.Value))
                    {
                        badUrl = m.Value;
                        break;
                    }
                }
            }

            if (!hasDangerousFlag && badUrl is null) return null;

            var detail = hasDangerousFlag
                ? "브라우저 바로가기(.lnk)에 악성 확장 로드/원격 디버깅/프록시 인자가 주입되어 있습니다."
                : $"브라우저 바로가기(.lnk)에 외부 강제 접속 URL({badUrl})이 주입되어 있습니다(MZK 대표 하이재킹 유형).";

            return new MalwareThreatItem
            {
                Stage = MalwareScanStage.BrowserHijack,
                ThreatName = "Hijacker.Browser.ShortcutInjection",
                CategoryLabel = "브라우저 바로가기 변조",
                Severity = hasDangerousFlag ? ThreatSeverity.Critical : ThreatSeverity.High,
                RiskScore = hasDangerousFlag ? 90 : 80,
                TargetPath = lnkPath,
                TargetFileExistedAtScan = true,
                Sha256 = ComputeFileSha256Safe(lnkPath),
                SignatureLabel = "바로가기(.lnk) 분석",
                Description = detail,
                ActionType = RemediationActionType.CleanBrowserShortcut,
                RecommendedForCure = true
            };
        }
        catch
        {
            return null;
        }
    }

    private static bool IsTrustedOfficialBrowserUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return false;
        var host = uri.Host;
        return host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
               host.Equals("127.0.0.1", StringComparison.Ordinal) ||
               host.Equals("google.com", StringComparison.OrdinalIgnoreCase) ||
               host.EndsWith(".google.com", StringComparison.OrdinalIgnoreCase) ||
               host.Equals("microsoft.com", StringComparison.OrdinalIgnoreCase) ||
               host.EndsWith(".microsoft.com", StringComparison.OrdinalIgnoreCase) ||
               host.Equals("naver.com", StringComparison.OrdinalIgnoreCase) ||
               host.EndsWith(".naver.com", StringComparison.OrdinalIgnoreCase);
    }

    private static int ScanSystemAndNetworkIntegrity(ConcurrentBag<MalwareThreatItem> findings, CancellationToken ct)
    {
        int scanned = 0;

        // 4A. HOSTS file hijacking check
        ct.ThrowIfCancellationRequested();
        var hostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");
        scanned++;
        try
        {
            if (File.Exists(hostsPath))
            {
                var hostsText = File.ReadAllText(hostsPath);
                foreach (var item in AnalyzeHostsContent(hostsText, hostsPath))
                {
                    findings.Add(item);
                }
            }
        }
        catch { }

        // 4B. WinInet Proxy / PAC AutoConfigURL check
        ct.ThrowIfCancellationRequested();
        scanned++;
        try
        {
            using var inet = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
            if (inet is not null)
            {
                var proxyEnable = Convert.ToInt32(inet.GetValue("ProxyEnable") ?? 0);
                var proxyServer = inet.GetValue("ProxyServer")?.ToString()?.Trim() ?? string.Empty;
                var pacUrl = inet.GetValue("AutoConfigURL")?.ToString()?.Trim() ?? string.Empty;

                if ((proxyEnable == 1 && !string.IsNullOrWhiteSpace(proxyServer)) || !string.IsNullOrWhiteSpace(pacUrl))
                {
                    findings.Add(new MalwareThreatItem
                    {
                        Stage = MalwareScanStage.SystemAndNetworkRepair,
                        ThreatName = "Hijacker.Network.ProxyOrPac",
                        CategoryLabel = "시스템 프록시/PAC 변조",
                        Severity = ThreatSeverity.High,
                        RiskScore = 80,
                        TargetPath = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                        EntryName = !string.IsNullOrWhiteSpace(pacUrl) ? pacUrl : proxyServer,
                        SignatureLabel = "WinInet 네트워크 설정",
                        Description = $"인터넷 프록시 또는 PAC 자동 구성 스크립트가 활성화되어 있습니다(Proxy={proxyServer}, PAC={pacUrl}).",
                        ActionType = RemediationActionType.ResetProxySettings,
                        RecommendedForCure = false
                    });
                }
            }
        }
        catch { }

        // 4C. Windows Defender high-risk exclusion injection check (Standard + GPO Policies: Paths, Extensions, & Processes!)
        ct.ThrowIfCancellationRequested();
        scanned++;
        var sysDrive = (Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows)) ?? @"C:\").TrimEnd('\\');
        string[] defenderExclBases =
        {
            @"SOFTWARE\Microsoft\Windows Defender\Exclusions",
            @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions"
        };
        foreach (var defBase in defenderExclBases)
        try
        {
            using var exclPaths = Registry.LocalMachine.OpenSubKey($@"{defBase}\Paths");
            if (exclPaths is not null)
            {
                foreach (var valName in exclPaths.GetValueNames())
                {
                    var norm = valName.Trim().TrimEnd('\\');
                    bool isDangerousBroadExclusion =
                        norm.Equals(sysDrive, StringComparison.OrdinalIgnoreCase) ||
                        norm.Equals($@"{sysDrive}\Users", StringComparison.OrdinalIgnoreCase) ||
                        norm.Equals($@"{sysDrive}\Users\Public", StringComparison.OrdinalIgnoreCase) ||
                        norm.Equals($@"{sysDrive}\ProgramData", StringComparison.OrdinalIgnoreCase) ||
                        norm.EndsWith(@"\AppData\Local\Temp", StringComparison.OrdinalIgnoreCase) ||
                        norm.EndsWith(@"\AppData\Roaming", StringComparison.OrdinalIgnoreCase) ||
                        norm.EndsWith(@"\Downloads", StringComparison.OrdinalIgnoreCase) ||
                        norm.Equals($@"{sysDrive}\Windows\Temp", StringComparison.OrdinalIgnoreCase);

                    if (isDangerousBroadExclusion)
                    {
                        findings.Add(new MalwareThreatItem
                        {
                            Stage = MalwareScanStage.SystemAndNetworkRepair,
                            ThreatName = "DefenseEvasion.DefenderPathExclusion",
                            CategoryLabel = "Defender 경로 예외 악성 주입",
                            Severity = ThreatSeverity.Critical,
                            RiskScore = 95,
                            TargetPath = $@"HKLM\{defBase}\Paths",
                            EntryName = valName,
                            SignatureLabel = "Windows Defender 정책",
                            Description = $"악성코드가 백신 검사를 회피하기 위해 고위험 공용/임시 경로를 Defender 예외에 등록했습니다: {valName}",
                            ActionType = RemediationActionType.RemoveDefenderExclusion,
                            RecommendedForCure = true
                        });
                    }
                }
            }

            using var exclExts = Registry.LocalMachine.OpenSubKey($@"{defBase}\Extensions");
            if (exclExts is not null)
            {
                foreach (var valName in exclExts.GetValueNames())
                {
                    var extNorm = valName.Trim().TrimStart('.');
                    if (extNorm is "exe" or "dll" or "ps1" or "bat" or "vbs" or "js" or "sys")
                    {
                        findings.Add(new MalwareThreatItem
                        {
                            Stage = MalwareScanStage.SystemAndNetworkRepair,
                            ThreatName = "DefenseEvasion.DefenderExtExclusion",
                            CategoryLabel = "Defender 확장자 예외 악성 주입",
                            Severity = ThreatSeverity.Critical,
                            RiskScore = 95,
                            TargetPath = $@"HKLM\{defBase}\Extensions",
                            EntryName = valName,
                            SignatureLabel = "Windows Defender 정책",
                            Description = $"실행/스크립트 확장자(.{extNorm}) 전체가 Windows Defender 검사 예외로 등록되어 있습니다!",
                            ActionType = RemediationActionType.RemoveDefenderExclusion,
                            RecommendedForCure = true
                        });
                    }
                }
            }

            using var exclProcs = Registry.LocalMachine.OpenSubKey($@"{defBase}\Processes");
            if (exclProcs is not null)
            {
                foreach (var valName in exclProcs.GetValueNames())
                {
                    var procNorm = Path.GetFileName(valName.Trim());
                    if (procNorm.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase) ||
                        procNorm.Equals("cmd.exe", StringComparison.OrdinalIgnoreCase) ||
                        procNorm.Equals("wscript.exe", StringComparison.OrdinalIgnoreCase) ||
                        procNorm.Equals("mshta.exe", StringComparison.OrdinalIgnoreCase))
                    {
                        findings.Add(new MalwareThreatItem
                        {
                            Stage = MalwareScanStage.SystemAndNetworkRepair,
                            ThreatName = "DefenseEvasion.DefenderProcExclusion",
                            CategoryLabel = "Defender LOLBin 프로세스 예외 주입",
                            Severity = ThreatSeverity.Critical,
                            RiskScore = 95,
                            TargetPath = $@"HKLM\{defBase}\Processes",
                            EntryName = valName,
                            SignatureLabel = "Windows Defender 정책",
                            Description = $"공격에 악용되는 시스템 도구({procNorm})가 Windows Defender 검사 예외로 등록되어 있습니다!",
                            ActionType = RemediationActionType.RemoveDefenderExclusion,
                            RecommendedForCure = true
                        });
                    }
                }
            }
        }
        catch { }

        return scanned;
    }

    public static IReadOnlyList<MalwareThreatItem> AnalyzeHostsContent(string hostsContent, string hostsPath)
    {
        var results = new List<MalwareThreatItem>();
        if (string.IsNullOrWhiteSpace(hostsContent)) return results;

        var lines = hostsContent.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
        foreach (var rawLine in lines)
        {
            var trimmed = rawLine.Trim();
            if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith('#')) continue;

            var commentIdx = trimmed.IndexOf('#');
            var effective = commentIdx >= 0 ? trimmed[..commentIdx].Trim() : trimmed;
            var parts = effective.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) continue;

            var ip = parts[0];
            var domains = parts.Skip(1).ToList();

            if (domains.All(d =>
                d.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
                d.Equals("localhost.localdomain", StringComparison.OrdinalIgnoreCase) ||
                d.EndsWith(".docker.internal", StringComparison.OrdinalIgnoreCase) ||
                d.EndsWith(".local", StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            bool targetsProtectedDomain = domains.Any(d =>
                ProtectedHijackTargetDomains.Any(p => d.Contains(p, StringComparison.OrdinalIgnoreCase)));
            bool isLoopbackOrPrivateLan = ip.StartsWith("127.", StringComparison.Ordinal) ||
                                          ip == "0.0.0.0" ||
                                          ip == "::1" ||
                                          ip == "::" ||
                                          IsPrivateRfc1918Ip(ip);
            bool redirectsToExternalIp = !isLoopbackOrPrivateLan;

            if (targetsProtectedDomain || redirectsToExternalIp)
            {
                results.Add(new MalwareThreatItem
                {
                    Stage = MalwareScanStage.SystemAndNetworkRepair,
                    ThreatName = targetsProtectedDomain ? "Hijacker.Hosts.SecurityOrPortalBlock" : "Hijacker.Hosts.ExternalRedirect",
                    CategoryLabel = "HOSTS DNS 하이재킹",
                    Severity = targetsProtectedDomain ? ThreatSeverity.Critical : ThreatSeverity.High,
                    RiskScore = targetsProtectedDomain ? 92 : 78,
                    TargetPath = hostsPath,
                    EntryName = trimmed,
                    SignatureLabel = "Windows HOSTS 파일",
                    Description = targetsProtectedDomain
                        ? $"백신/보안/금융/포털 도메인을 차단 또는 피싱 서버로 변조하는 HOSTS 항목 감지: {trimmed}"
                        : $"외부 IP({ip})로 도메인을 강제 리다이렉션하는 HOSTS 항목 감지: {trimmed}",
                    ActionType = RemediationActionType.CleanHostsFile,
                    RecommendedForCure = targetsProtectedDomain
                });
            }
        }

        return results;
    }

    private static bool IsPrivateRfc1918Ip(string ipText)
    {
        if (!System.Net.IPAddress.TryParse(ipText, out var addr)) return false;
        if (addr.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false;
        var b = addr.GetAddressBytes();
        return b[0] == 10 ||
               (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
               (b[0] == 192 && b[1] == 168);
    }

    private (int Scanned, int TruncatedRoots) ScanFilesForMode(
        MalwareScanMode mode,
        GuardPolicy policy,
        string? customTargetPath,
        ConcurrentBag<MalwareThreatItem> findings,
        Action<int, string, double> onProgress,
        CancellationToken ct)
    {
        if (mode == MalwareScanMode.SingleFileScan)
        {
            if (string.IsNullOrWhiteSpace(customTargetPath) || !File.Exists(customTargetPath)) return (0, 0);
            onProgress(1, customTargetPath, 50);
            var single = _threatScanner.ScanFile(customTargetPath, policy, includeClean: true);
            if (single is not null)
            {
                findings.Add(ConvertScanFindingToThreatItem(single, MalwareScanStage.VirusSignatureAndFile, null));
            }
            onProgress(1, customTargetPath, 100);
            return (1, 0);
        }

        var roots = new List<(string Path, int MaxFiles, int MaxDepth)>();
        bool trackVisitedDirs = false;

        if (mode == MalwareScanMode.CustomFolderScan && !string.IsNullOrWhiteSpace(customTargetPath) && Directory.Exists(customTargetPath))
        {
            roots.Add((customTargetPath, int.MaxValue, 64));
        }
        else if (mode == MalwareScanMode.QuickScan)
        {
            trackVisitedDirs = true;
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var dirs = new[]
            {
                Path.Combine(userProfile, "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp")
            };
            foreach (var d in dirs.Where(Directory.Exists))
            {
                roots.Add((d, 5_000, 12));
            }
        }
        else if (mode == MalwareScanMode.MzkDeepScan)
        {
            trackVisitedDirs = true;
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var publicDir = Environment.GetEnvironmentVariable("PUBLIC") ?? @"C:\Users\Public";
            var sysRoot = Path.GetPathRoot(winDir) ?? @"C:\";

            // 100% full-depth unlimited streaming BFS across ALL 15 Windows malware/PUP drop zones.
            // High-risk paths (Downloads/Desktop/Startup/Temp) are enqueued first; visitedDirs prevents double-scanning overlaps.
            // sysRoot (C:\) stays depth=1 to catch root drops (e.g. C:\a.exe, C:\Temp\a.exe) without scanning C:\Windows\WinSxS.
            var mzkDirs = new (string Path, int MaxFiles, int MaxDepth)[]
            {
                (Path.Combine(userProfile, "Downloads"), int.MaxValue, 64),
                (Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), int.MaxValue, 64),
                (Environment.GetFolderPath(Environment.SpecialFolder.Startup), int.MaxValue, 64),
                (Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), int.MaxValue, 64),
                (Path.Combine(localApp, "Temp"), int.MaxValue, 64),
                (Path.Combine(winDir, "Temp"), int.MaxValue, 64),
                (Path.Combine(winDir, "Tasks"), int.MaxValue, 64),
                (Path.Combine(winDir, "Debug"), int.MaxValue, 64),
                (publicDir, int.MaxValue, 64),
                (Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), int.MaxValue, 64),
                (Path.Combine(userProfile, "AppData", "LocalLow"), int.MaxValue, 64),
                (Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), int.MaxValue, 64),
                (localApp, int.MaxValue, 64),
                (Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), int.MaxValue, 64),
                (sysRoot, int.MaxValue, 1)
            };
            foreach (var item in mzkDirs)
            {
                if (!string.IsNullOrWhiteSpace(item.Path) && Directory.Exists(item.Path))
                {
                    roots.Add(item);
                }
            }
        }
        else if (mode == MalwareScanMode.FullSystemScan)
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (!drive.IsReady) continue;
                if (drive.DriveType is not (DriveType.Fixed or DriveType.Removable)) continue;
                roots.Add((drive.RootDirectory.FullName, int.MaxValue, 64));
            }
        }

        if (roots.Count == 0) return (0, 0);

        // Bounded streaming Producer-Consumer pipeline:
        // Never buffers all file paths in RAM (max 2,048 queued paths = ~0.5 MB regardless of disk size!).
        // Use a linked pipelineCts so if Parallel.ForEach ever faults or cancels, the producer unblocks immediately with zero deadlock!
        using var fileQueue = new BlockingCollection<string>(boundedCapacity: 2048);
        using var pipelineCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        int truncatedRoots = 0;
        int completedRoots = 0;
        int discoveredFiles = 0;
        int scanned = 0;
        int totalRoots = roots.Count;

        var producerTask = Task.Run(() =>
        {
            var visitedDirs = trackVisitedDirs ? new HashSet<string>(StringComparer.OrdinalIgnoreCase) : null;
            var pToken = pipelineCts.Token;
            try
            {
                foreach (var (rootPath, maxF, maxD) in roots)
                {
                    pToken.ThrowIfCancellationRequested();
                    bool hitCap = StreamTargetFilesBfs(rootPath, fileQueue, maxF, maxD, visitedDirs, ref discoveredFiles, pToken);
                    if (hitCap) Interlocked.Increment(ref truncatedRoots);
                    Interlocked.Increment(ref completedRoots);
                }
            }
            catch (OperationCanceledException) { }
            finally
            {
                fileQueue.CompleteAdding();
            }
        }, CancellationToken.None);

        try
        {
            Parallel.ForEach(
                fileQueue.GetConsumingEnumerable(pipelineCts.Token),
                new ParallelOptions
                {
                    MaxDegreeOfParallelism = Math.Clamp(Environment.ProcessorCount / 2, 2, 4),
                    CancellationToken = pipelineCts.Token
                },
                file =>
                {
                    var finding = _threatScanner.ScanFile(file, policy, includeClean: false);
                    if (finding is not null && finding.RiskScore >= 45)
                    {
                        findings.Add(ConvertScanFindingToThreatItem(finding, MalwareScanStage.VirusSignatureAndFile, null));
                    }

                    int count = Interlocked.Increment(ref scanned);
                    if (count % 25 == 0)
                    {
                        int doneRoots = Volatile.Read(ref completedRoots);
                        int disc = Math.Max(count, Volatile.Read(ref discoveredFiles));
                        double pct = doneRoots >= totalRoots
                            ? Math.Min(99.5, (double)count / disc * 100.0)
                            : Math.Min(95.0, ((doneRoots + (double)count / (disc + 200.0)) / totalRoots) * 100.0);
                        onProgress(count, file, pct);
                    }
                });
        }
        finally
        {
            // Cancel producer before awaiting so a full BlockingCollection can never deadlock on consumer exit!
            try { pipelineCts.Cancel(); } catch { }
            try { producerTask.GetAwaiter().GetResult(); } catch { }
        }

        if (scanned > 0)
        {
            onProgress(scanned, "파일/시그니처 검사 완료", 100.0);
        }

        // Stage 5B: Hidden NTFS Alternate Data Stream (ADS) audit on high-risk drop zones (catches invisible file:payload.exe!)
        if (mode is MalwareScanMode.MzkDeepScan or MalwareScanMode.FullSystemScan && !ct.IsCancellationRequested)
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var adsDirs = new[]
            {
                Path.Combine(userProfile, "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
                Environment.GetEnvironmentVariable("PUBLIC") ?? @"C:\Users\Public"
            }.Where(d => !string.IsNullOrWhiteSpace(d) && Directory.Exists(d))
             .Distinct(StringComparer.OrdinalIgnoreCase);

            foreach (var dir in adsDirs)
            {
                ct.ThrowIfCancellationRequested();
                foreach (var adsHit in NtfsAdsScanner.ScanDirectoryTopLevel(dir, maxFiles: 2500, ct))
                {
                    findings.Add(adsHit);
                }
            }
        }

        return (scanned, truncatedRoots);
    }

    private static string? ResolveLatestMpCmdRunPath()
    {
        // Prefer latest active Windows 10/11 Defender Platform binary in ProgramData
        try
        {
            var platformRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Microsoft", "Windows Defender", "Platform");
            if (Directory.Exists(platformRoot))
            {
                var latest = Directory.EnumerateDirectories(platformRoot)
                    .OrderByDescending(d => d, StringComparer.OrdinalIgnoreCase)
                    .Select(d => Path.Combine(d, "MpCmdRun.exe"))
                    .FirstOrDefault(File.Exists);
                if (!string.IsNullOrWhiteSpace(latest)) return latest;
            }
        }
        catch { }

        var fallback = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "Windows Defender", "MpCmdRun.exe");
        return File.Exists(fallback) ? fallback : null;
    }

    private static async Task<(int Checked, int Timeouts)> RunDefenderCrossCheckAsync(ConcurrentBag<MalwareThreatItem> findings, CancellationToken ct)
    {
        var mpCmdRun = ResolveLatestMpCmdRunPath();
        if (string.IsNullOrWhiteSpace(mpCmdRun)) return (0, 0);

        var targets = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetEnvironmentVariable("PUBLIC") ?? @"C:\Users\Public"
        }.Where(d => !string.IsNullOrWhiteSpace(d) && Directory.Exists(d))
         .Distinct(StringComparer.OrdinalIgnoreCase)
         .ToList();

        int checkedTargets = 0;
        int timeouts = 0;

        foreach (var target in targets)
        {
            ct.ThrowIfCancellationRequested();
            checkedTargets++;
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = mpCmdRun,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };
                psi.ArgumentList.Add("-Scan");
                psi.ArgumentList.Add("-ScanType");
                psi.ArgumentList.Add("3");
                psi.ArgumentList.Add("-DisableRemediation");
                psi.ArgumentList.Add("-File");
                psi.ArgumentList.Add(target);

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

                if (proc is null) continue;
                int helperPid = proc.Id;
                using (proc)
                try
                {
                    using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    timeoutCts.CancelAfter(TimeSpan.FromSeconds(120));

                    // Read BOTH stdout and stderr concurrently to eliminate pipe deadlocks!
                    var stdoutTask = proc.StandardOutput.ReadToEndAsync(timeoutCts.Token);
                    var stderrTask = proc.StandardError.ReadToEndAsync(timeoutCts.Token);
                    await proc.WaitForExitAsync(timeoutCts.Token);
                    var stdout = await stdoutTask;
                    _ = await stderrTask;

                    if (proc.ExitCode == 2)
                    {
                        var parsedThreats = ParseAllDefenderThreats(stdout, target);
                        foreach (var (threatName, rawFile) in parsedThreats)
                        {
                            // Handle container syntax (e.g. "C:\Downloads\evil.zip->payload.exe") cleanly
                            var actualFile = rawFile.Contains("->", StringComparison.Ordinal)
                                ? rawFile[..rawFile.IndexOf("->", StringComparison.Ordinal)].Trim()
                                : rawFile;
                            bool canQuarantine = File.Exists(actualFile) && !QuarantineManager.IsProtectedSystemOrSelfPath(actualFile);

                            findings.Add(new MalwareThreatItem
                            {
                                Stage = MalwareScanStage.DefenderCrossCheck,
                                ThreatName = threatName,
                                CategoryLabel = "Defender 글로벌 시그니처 탐지",
                                Severity = ThreatSeverity.Critical,
                                RiskScore = 100,
                                TargetPath = actualFile,
                                Sha256 = canQuarantine ? ComputeFileSha256Safe(actualFile) : string.Empty,
                                SignatureLabel = "Microsoft Defender 엔진 교차검증",
                                Description = $"Windows Defender 글로벌 바이러스 DB에서 위협이 탐지되었습니다: {threatName} ({rawFile})",
                                ActionType = canQuarantine ? RemediationActionType.QuarantineFile : RemediationActionType.ManualReview,
                                RecommendedForCure = canQuarantine
                            });
                        }
                    }
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    timeouts++;
                    try { proc.Kill(true); } catch { }
                }
                catch (OperationCanceledException)
                {
                    try { proc.Kill(true); } catch { }
                    throw;
                }
                finally
                {
                    InternalHelperProcessRegistry.Unregister(helperPid);
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }

        return (checkedTargets, timeouts);
    }

    private static List<(string ThreatName, string FilePath)> ParseAllDefenderThreats(string output, string fallbackTarget)
    {
        var results = new List<(string, string)>();
        string currentThreat = "Malware.Defender.Detected";

        foreach (var rawLine in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = rawLine.Trim();
            if (trimmed.StartsWith("Threat", StringComparison.OrdinalIgnoreCase) && trimmed.Contains(':'))
            {
                var val = trimmed[(trimmed.IndexOf(':') + 1)..].Trim();
                if (!string.IsNullOrWhiteSpace(val)) currentThreat = val;
            }
            else if ((trimmed.StartsWith("file", StringComparison.OrdinalIgnoreCase) ||
                      trimmed.StartsWith("containerfile", StringComparison.OrdinalIgnoreCase)) &&
                     trimmed.Contains(':'))
            {
                var val = trimmed[(trimmed.IndexOf(':') + 1)..].Trim().TrimEnd(')');
                if (!string.IsNullOrWhiteSpace(val))
                {
                    results.Add((currentThreat, val));
                }
            }
        }

        if (results.Count == 0)
        {
            results.Add((currentThreat, fallbackTarget));
        }

        return results;
    }

    private static MalwareThreatItem ConvertScanFindingToThreatItem(
        ScanFinding finding,
        MalwareScanStage stage,
        int? pid,
        long processCreationTimeFileTimeUtc = 0,
        string? hostProcessPath = null)
    {
        var reasonsText = finding.Reasons.Count > 0 ? string.Join(" | ", finding.Reasons) : "이상 없음 (정상 파일)";
        var threatName = DeriveThreatName(finding);
        bool isProtected = QuarantineManager.IsProtectedSystemOrSelfPath(finding.FilePath);

        return new MalwareThreatItem
        {
            Stage = stage,
            ThreatName = threatName,
            CategoryLabel = finding.RiskScore >= 80 ? "고위험 바이러스/악성코드" : (finding.RiskScore >= 40 ? "의심 파일/PUA" : "정상 파일"),
            Severity = finding.Severity,
            RiskScore = finding.RiskScore,
            TargetPath = finding.FilePath,
            ProcessId = pid,
            ProcessCreationTimeFileTimeUtc = processCreationTimeFileTimeUtc,
            HostProcessPath = hostProcessPath ?? (pid.HasValue ? finding.FilePath : null),
            TargetFileExistedAtScan = File.Exists(finding.FilePath),
            Sha256 = finding.Sha256,
            SignatureLabel = finding.Signature.DisplayLabel,
            Description = reasonsText,
            ActionType = finding.RiskScore < 40 || isProtected
                ? RemediationActionType.ManualReview
                : (pid.HasValue ? RemediationActionType.TerminateAndQuarantine : RemediationActionType.QuarantineFile),
            RecommendedForCure = finding.RiskScore >= 60 && !isProtected
        };
    }

    private static string DeriveThreatName(ScanFinding finding)
    {
        var joined = string.Join(" ", finding.Reasons);
        if (joined.Contains("EICAR", StringComparison.OrdinalIgnoreCase)) return "EICAR-Standard-AntiVirus-Test";
        if (joined.Contains("SupplyChain.DllSideloading.ProxyHijack", StringComparison.OrdinalIgnoreCase)) return "SupplyChain.DllSideloading.ProxyHijack";
        if (joined.Contains("SupplyChain.DllSideloading.StagedProxyDll", StringComparison.OrdinalIgnoreCase)) return "SupplyChain.DllSideloading.StagedProxyDll";
        if (joined.Contains("Trojan.Masquerade.HiddenPeExecutable", StringComparison.OrdinalIgnoreCase)) return "Trojan.Masquerade.HiddenPeExecutable";
        if (joined.Contains("Trojan.Stego.", StringComparison.OrdinalIgnoreCase)) return "Trojan.Stego.HiddenImagePayload";
        if (joined.Contains("Shellcode.RawBlob.", StringComparison.OrdinalIgnoreCase)) return "Shellcode.RawBlob.DisguisedLoader";
        if (joined.Contains("Exploit.PDF.", StringComparison.OrdinalIgnoreCase)) return "Exploit.PDF.MaliciousAction";
        if (joined.Contains("Shellcode.Win64.ApiHashPrologue", StringComparison.OrdinalIgnoreCase)) return "Shellcode.Win64.ApiHashPrologue";
        if (joined.Contains("SupplyChain.JS.ObfuscatedCredExfil", StringComparison.OrdinalIgnoreCase)) return "SupplyChain.JS.ObfuscatedCredExfil";
        if (joined.Contains("Macro.Office.AutoExecShellDropper", StringComparison.OrdinalIgnoreCase)) return "Macro.Office.AutoExecShellDropper";
        if (joined.Contains("Miner.Multi.CryptoMiner", StringComparison.OrdinalIgnoreCase)) return "Miner.Multi.CryptoMiner";
        if (joined.Contains("Trojan.Win32.BrowserStealer", StringComparison.OrdinalIgnoreCase)) return "Trojan.Win32.BrowserStealer";
        if (joined.Contains("Backdoor.Multi.ReverseShell", StringComparison.OrdinalIgnoreCase)) return "Backdoor.Multi.ReverseShell";
        if (joined.Contains("Ransom.Win32.ShadowWiper", StringComparison.OrdinalIgnoreCase)) return "Ransom.Win32.ShadowWiper";
        if (joined.Contains("PUA.Win32.BrowserHijacker", StringComparison.OrdinalIgnoreCase)) return "PUA.Win32.BrowserHijacker";
        if (joined.Contains("Trojan.Win32.CredDumperArtifact", StringComparison.OrdinalIgnoreCase)) return "Trojan.Win32.CredDumperArtifact";
        if (joined.Contains("IOC", StringComparison.OrdinalIgnoreCase)) return "Malware.IOC.KnownHash";
        if (joined.Contains("이중 확장자", StringComparison.OrdinalIgnoreCase)) return "Trojan.Masquerade.DoubleExtension";
        if (joined.Contains("PE 정적 분석", StringComparison.OrdinalIgnoreCase)) return "Heuristic.PE.SuspiciousBinary";
        if (finding.FilePath.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)) return "Trojan.Archive.MaliciousZip";
        if (finding.FilePath.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)) return "Trojan.LNK.WeaponizedShortcut";
        if (ScriptFileAnalyzer.IsSupportedScriptExtension(Path.GetExtension(finding.FilePath))) return "Trojan.Script.MaliciousDropper";
        return finding.RiskScore >= 40 ? "Heuristic.Win32.SuspiciousFile" : "Clean.VerifiedFile";
    }

    /// <summary>
    /// Bounded-memory streaming Breadth-First Search (BFS) directory enumerator using unified ThreatScanner.ScannableExtensions.
    /// Pushes discovered files directly into a bounded BlockingCollection so RAM stays O(1) even with unlimited maxFiles.
    /// Returns true only if a finite maxFiles cap was reached.
    /// </summary>
    private static bool StreamTargetFilesBfs(
        string rootDir,
        BlockingCollection<string> targetQueue,
        int maxFiles,
        int maxDepth,
        HashSet<string>? visitedDirs,
        ref int totalDiscovered,
        CancellationToken ct)
    {
        var queue = new Queue<(string Dir, int Depth)>();
        var enumOpts = new System.IO.EnumerationOptions
        {
            AttributesToSkip = FileAttributes.ReparsePoint,
            IgnoreInaccessible = true,
            RecurseSubdirectories = false
        };

        string normRoot;
        try { normRoot = Path.GetFullPath(rootDir).TrimEnd('\\', '/'); }
        catch { normRoot = rootDir; }

        if (visitedDirs is not null && !visitedDirs.Add(normRoot))
        {
            return false;
        }

        queue.Enqueue((rootDir, 0));
        int added = 0;

        while (queue.Count > 0 && !ct.IsCancellationRequested)
        {
            if (maxFiles < int.MaxValue && added >= maxFiles) return true;
            var (dir, depth) = queue.Dequeue();
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", enumOpts))
                {
                    ct.ThrowIfCancellationRequested();
                    if (maxFiles < int.MaxValue && added >= maxFiles) return true;

                    var ext = Path.GetExtension(file);
                    bool scannable = ThreatScanner.ScannableExtensions.Contains(ext) ||
                                     PolyglotAndMagicSniffer.IsDeepSniffCandidate(ext);

                    if (scannable)
                    {
                        Interlocked.Increment(ref totalDiscovered);
                        targetQueue.Add(file, ct);
                        added++;
                    }
                }

                if (depth >= maxDepth) continue;

                foreach (var sub in Directory.EnumerateDirectories(dir, "*", enumOpts))
                {
                    var name = Path.GetFileName(sub);
                    if (SkippedFullScanDirNames.Contains(name)) continue;
                    if (sub.Contains(@"\AegisSentinel\Quarantine", StringComparison.OrdinalIgnoreCase) ||
                        sub.Contains(@"\AegisSentinel\Vault", StringComparison.OrdinalIgnoreCase) ||
                        sub.Contains(@"\AegisSentinel\RecoveryVault", StringComparison.OrdinalIgnoreCase) ||
                        sub.Contains(@"\AegisSentinel\RemediationBackups", StringComparison.OrdinalIgnoreCase) ||
                        sub.Contains(@"\ProgramData\Microsoft\Windows Defender", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    if (visitedDirs is not null)
                    {
                        string normSub;
                        try { normSub = Path.GetFullPath(sub).TrimEnd('\\', '/'); }
                        catch { normSub = sub; }
                        if (!visitedDirs.Add(normSub)) continue;
                    }

                    queue.Enqueue((sub, depth + 1));
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }

        return maxFiles < int.MaxValue && added >= maxFiles;
    }

    private static IReadOnlyList<MalwareThreatItem> DeduplicateAndOrder(IEnumerable<MalwareThreatItem> raw)
    {
        var map = new Dictionary<string, MalwareThreatItem>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in raw)
        {
            // Merge duplicate file threats discovered across Stage 1 (TerminateAndQuarantine), Stage 5 (QuarantineFile), and Stage 6 (Defender)
            bool isFileRemediation = item.ActionType is RemediationActionType.QuarantineFile or RemediationActionType.TerminateAndQuarantine;
            var key = isFileRemediation
                ? $"FILE|{item.TargetPath}"
                : $"{item.TargetPath}|{item.EntryName}|{item.ActionType}";

            if (!map.TryGetValue(key, out var existing))
            {
                map[key] = item;
                continue;
            }

            if (item.RiskScore > existing.RiskScore ||
                (item.RiskScore == existing.RiskScore && item.ActionType == RemediationActionType.TerminateAndQuarantine && existing.ActionType == RemediationActionType.QuarantineFile))
            {
                var mergedSha = !string.IsNullOrWhiteSpace(item.Sha256) ? item.Sha256 : existing.Sha256;
                map[key] = existing.ProcessId.HasValue && !item.ProcessId.HasValue
                    ? item with
                    {
                        ProcessId = existing.ProcessId,
                        ProcessCreationTimeFileTimeUtc = existing.ProcessCreationTimeFileTimeUtc,
                        HostProcessPath = existing.HostProcessPath,
                        Sha256 = mergedSha,
                        ActionType = RemediationActionType.TerminateAndQuarantine
                    }
                    : (mergedSha != item.Sha256 ? item with { Sha256 = mergedSha } : item);
            }
            else if (item.ProcessId.HasValue && !existing.ProcessId.HasValue)
            {
                var mergedSha = !string.IsNullOrWhiteSpace(existing.Sha256) ? existing.Sha256 : item.Sha256;
                map[key] = existing with
                {
                    ProcessId = item.ProcessId,
                    ProcessCreationTimeFileTimeUtc = item.ProcessCreationTimeFileTimeUtc,
                    HostProcessPath = item.HostProcessPath,
                    Sha256 = mergedSha,
                    ActionType = RemediationActionType.TerminateAndQuarantine
                };
            }
            else if (string.IsNullOrWhiteSpace(existing.Sha256) && !string.IsNullOrWhiteSpace(item.Sha256))
            {
                map[key] = existing with { Sha256 = item.Sha256 };
            }
        }

        return map.Values
            .OrderByDescending(x => x.RiskScore)
            .ThenBy(x => x.Stage)
            .ToList();
    }

    private static string ComputeFileSha256Safe(string filePath)
    {
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(fs));
        }
        catch
        {
            return string.Empty;
        }
    }
}
