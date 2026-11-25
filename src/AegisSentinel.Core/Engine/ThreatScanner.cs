using System.Collections.Concurrent;
using System.Diagnostics;
using AegisSentinel.Core.Models;
using AegisSentinel.Core.Services;

namespace AegisSentinel.Core.Engine;

public sealed record ScanProgressReport(int ScannedCount, int FindingCount, string CurrentFile);

public sealed class ThreatScanner
{
    public static readonly HashSet<string> ScannableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".com", ".sys", ".ocx", ".msi", ".cpl", ".pif", ".xll",
        ".ps1", ".bat", ".cmd", ".vbs", ".js", ".mjs", ".cjs", ".jse", ".vbe", ".hta", ".wsf", ".sct", ".py",
        ".lnk", ".iso", ".vhd", ".vhdx", ".img", ".chm", ".zip", ".jar", ".reg", ".msc",
        ".doc", ".docm", ".xls", ".xlsm", ".pptm", ".rtf", ".hwp", ".hwpx"
    };

    private static readonly HashSet<string> AuthenticodeCapableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".sys", ".ocx", ".msi", ".cpl", ".cat", ".ps1", ".vbs", ".js", ".wsf"
    };

    private readonly SignatureVerifier _signatureVerifier;
    private readonly ThreatIntelStore _intelStore;
    private readonly ProcessController _processController;

    public ThreatScanner(
        SignatureVerifier signatureVerifier,
        ThreatIntelStore intelStore,
        ProcessController processController)
    {
        _signatureVerifier = signatureVerifier;
        _intelStore = intelStore;
        _processController = processController;
    }

    public static bool HasMarkOfTheWeb(string filePath)
    {
        try
        {
            var adsPath = filePath + ":Zone.Identifier";
            if (!File.Exists(adsPath))
            {
                return false;
            }

            var text = File.ReadAllText(adsPath);
            return text.Contains("ZoneId=3", StringComparison.OrdinalIgnoreCase) ||
                   text.Contains("ZoneId=4", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    public ScanFinding? ScanFile(string filePath, GuardPolicy policy, bool includeClean = false)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return null;
        }

        try
        {
            var ext = Path.GetExtension(filePath);
            var extLower = ext.ToLowerInvariant();
            var fileLen = new FileInfo(filePath).Length;
            bool isSmallEicarCandidate = fileLen > 0 && fileLen <= 128 &&
                                         (extLower is ".txt" or ".com" or ".bin" or ".dat" or "");
            bool isStandardScannable = ScannableExtensions.Contains(ext);
            bool isDeepSniffCandidate = !isStandardScannable && PolyglotAndMagicSniffer.IsDeepSniffCandidate(ext);

            if (!includeClean && !isStandardScannable && !isSmallEicarCandidate && !isDeepSniffCandidate)
            {
                return null;
            }

            // Ultra-fast (<0.1ms) beyond-AV magic-header / image-stego / raw-shellcode / weaponized-PDF sniff
            // for non-executable extensions (.png, .jpg, .pdf, .dat, .bin, .tmp, .pak, .txt, extensionless)
            var deepSniff = isDeepSniffCandidate
                ? PolyglotAndMagicSniffer.InspectFile(filePath, _signatureVerifier)
                : new DeepSniffResult(false, string.Empty, 0, ThreatSeverity.Info, string.Empty);

            if (!includeClean && !isStandardScannable && !isSmallEicarCandidate && !deepSniff.IsThreat)
            {
                return null;
            }

            var sig = AuthenticodeCapableExtensions.Contains(ext)
                ? _signatureVerifier.VerifyFile(filePath)
                : new SignatureInfo(SignatureStatus.Unsigned, string.Empty);
            var hasMotw = HasMarkOfTheWeb(filePath);
            bool isPeExt = extLower is ".exe" or ".dll" or ".scr" or ".sys" or ".ocx" or ".com" or ".cpl" or ".pif" or ".xll";

            // Avoid reading huge (>50 MB) validly signed vendor installers/game PAKs off SSD unless explicitly requested
            bool needSha = includeClean ||
                           isSmallEicarCandidate ||
                           deepSniff.IsThreat ||
                           (_intelStore.HasBlockedHashes && ((!sig.IsSigned && fileLen <= 250 * 1024 * 1024) || (sig.IsSigned && sig.Status != SignatureStatus.TrustedMicrosoft && fileLen <= 50 * 1024 * 1024))) ||
                           (!sig.IsSigned && fileLen <= 50 * 1024 * 1024);
            var sha256 = needSha ? SignatureVerifier.ComputeSha256Cached(filePath) : string.Empty;

            PeAnalysisResult? pe = isPeExt ? PeStaticAnalyzer.AnalyzeFile(filePath) : null;

            var reasons = new List<string>();
            int risk = 0;

            // -1. Polyglot / Masqueraded PE / Image Stego / Raw Shellcode / Weaponized PDF detection
            if (deepSniff.IsThreat)
            {
                risk = Math.Max(risk, deepSniff.RiskScore);
                reasons.Add($"[{deepSniff.ThreatName}] {deepSniff.Reason}");
            }

            // -0.5. Supply-Chain DLL Sideloading / Search-Order Hijacking detection (Anti-NIKKE engine!)
            var dllSideload = extLower == ".dll"
                ? DllSideloadingDetector.InspectDiskDll(filePath, sig, _signatureVerifier)
                : new DllSideloadFinding(false, string.Empty, 0, ThreatSeverity.Info, string.Empty);
            if (dllSideload.IsSideloading)
            {
                risk = Math.Max(risk, dllSideload.RiskScore);
                reasons.Add($"[{dllSideload.ThreatName}] {dllSideload.Reason}");
            }

            // 0. YARA-style virus/malware/coinminer/EICAR signature engine
            var sigMatch = SignaturePatternScanner.ScanFile(filePath, sig, sha256);
            if (sigMatch.IsMatched)
            {
                risk = Math.Max(risk, sigMatch.RiskScore);
                reasons.Add($"[{sigMatch.ThreatName}] {sigMatch.Reason}");
            }

            // 1. Known IOC SHA-256 hash match
            // Distinguish user-explicit IOC hashes from massive public feeds (MalwareBazaar/VirusShare),
            // which occasionally include dual-use open-source UAC helpers (e.g. electron-sudo elevate.exe) or Python venv shims.
            if (_intelStore.IsUserHashBlocked(sha256))
            {
                risk = 100;
                reasons.Add("위협 인텔리전스(사용자 IOC) 악성 해시 일치");
            }
            else if (sig.Status != SignatureStatus.TrustedMicrosoft && _intelStore.IsHashBlocked(sha256))
            {
                var leafName = Path.GetFileName(filePath);
                bool isKnownDualUseHelper =
                    leafName.Equals("elevate.exe", StringComparison.OrdinalIgnoreCase) &&
                    (ProcessRuleEvaluator.IsProtectedHostIdeProcess(filePath) ||
                     filePath.Contains(@"\AppData\Local\Programs\", StringComparison.OrdinalIgnoreCase) ||
                     filePath.Contains(@"\Program Files", StringComparison.OrdinalIgnoreCase));
                bool isPythonVenvShim = false;
                if (filePath.Contains(@"\Scripts\", StringComparison.OrdinalIgnoreCase))
                {
                    var parent = Path.GetDirectoryName(filePath);
                    var venvRoot = parent is not null ? Path.GetDirectoryName(parent) : null;
                    if (!string.IsNullOrEmpty(venvRoot) && File.Exists(Path.Combine(venvRoot, "pyvenv.cfg")))
                    {
                        isPythonVenvShim = true;
                    }
                }

                if (!isKnownDualUseHelper && !isPythonVenvShim)
                {
                    risk = 100;
                    reasons.Add("위협 인텔리전스(IOC) 악성 해시 일치");
                }
            }

            // 2. Invalid/tampered digital signature
            if (sig.Status == SignatureStatus.InvalidOrTampered)
            {
                risk += 75;
                reasons.Add($"디지털 서명 손상/위변조 ({sig.ErrorMessage})");
            }

            // 3. PE structural + packer + RWX + dangerous API heuristics
            if (pe is { IsValidPe: true })
            {
                if (!sig.IsSigned && pe.HeuristicScore >= 30)
                {
                    risk += pe.HeuristicScore;
                    reasons.Add($"PE 정적 분석 경고 ({pe.Summary})");
                }
                else if (sig.IsSigned && pe.HasRwxSection && pe.HasPackerSectionName)
                {
                    risk += 25;
                    reasons.Add($"서명 파일 내 비정상 패커/RWX 섹션 ({pe.Summary})");
                }
            }

            // 4. Unsigned internet-downloaded (MotW) or high-risk drop-path executable:
            // Only amplify risk when paired with an actual suspicious indicator (PE heuristic >= 30, script, or masquerading)
            // so benign unsigned open-source CLI tools or normal .zip archives in Downloads are not falsely flagged.
            bool isZip = extLower == ".zip";
            bool hasSuspiciousPeOrScript = (pe is { IsValidPe: true, HeuristicScore: >= 30 }) ||
                                           extLower is ".ps1" or ".bat" or ".cmd" or ".vbs" or ".js" or ".jse" or ".vbe" or ".wsf" or ".hta" or ".scr" or ".pif" or ".cpl";

            if (!isZip && !sig.IsSigned && hasMotw && ScannableExtensions.Contains(ext))
            {
                risk += hasSuspiciousPeOrScript ? 25 : 15;
                reasons.Add("인터넷 다운로드(Mark-of-the-Web) 미서명 실행/스크립트 파일");
            }

            // 5. High-risk temp/drop path unsigned binary
            if (!sig.IsSigned && ProcessRuleEvaluator.IsHighRiskDropPath(filePath) && isPeExt)
            {
                risk += hasSuspiciousPeOrScript ? 15 : 10;
                reasons.Add("고위험 임시/다운로드 경로의 미서명 바이너리");
            }

            // 6. Double-extension masquerading (skip outer .zip archives so clean 'invoice.pdf.zip' is judged by its contents)
            var name = Path.GetFileName(filePath);
            if (!isZip &&
                ScannableExtensions.Contains(ext) &&
                ZipArchiveAnalyzer.DisguisedDocMarkers.Any(m => name.Contains(m, StringComparison.OrdinalIgnoreCase)))
            {
                risk += 70;
                reasons.Add("문서/이미지 이중 확장자 위장 파일");
            }

            // 7. North Korean APT (.LNK shortcut & .ISO/.VHD/.CHM container) inspection
            if (ext.Equals(".lnk", StringComparison.OrdinalIgnoreCase))
            {
                var lnk = LnkAndContainerAnalyzer.AnalyzeLnkFile(filePath);
                if (lnk.IsMaliciousOrSuspicious)
                {
                    bool isWindowsStartMenuShortcut =
                        filePath.Contains(@"\Microsoft\Windows\Start Menu\Programs\", StringComparison.OrdinalIgnoreCase);
                    bool isBenignLocalShellShortcut =
                        !hasMotw &&
                        (!ProcessRuleEvaluator.IsHighRiskDropPath(filePath) || isWindowsStartMenuShortcut) &&
                        lnk.RiskScore <= 75 &&
                        lnk.Reasons.Count == 1 &&
                        (lnk.Reasons[0].EndsWith("(powershell)", StringComparison.OrdinalIgnoreCase) ||
                         lnk.Reasons[0].EndsWith("(pwsh)", StringComparison.OrdinalIgnoreCase) ||
                         lnk.Reasons[0].EndsWith("(cmd.exe)", StringComparison.OrdinalIgnoreCase));

                    risk = Math.Max(risk, isBenignLocalShellShortcut ? 35 : lnk.RiskScore);
                    reasons.AddRange(lnk.Reasons);
                }
            }
            else if (LnkAndContainerAnalyzer.IsSpearPhishingContainer(filePath))
            {
                bool isChm = ext.Equals(".chm", StringComparison.OrdinalIgnoreCase);
                // Ignore >150 MB legitimate OS install ISOs / WSL ext4.vhdx virtual disks;
                // phishing disk containers are typically small (<50 MB) and carry MotW.
                if ((isChm || fileLen <= 150 * 1024 * 1024) &&
                    (hasMotw || ProcessRuleEvaluator.IsHighRiskDropPath(filePath)))
                {
                    risk = Math.Max(risk, isChm ? 75 : (hasMotw ? 55 : 45));
                    reasons.Add($"스피어피싱 고위험 컨테이너/도움말 포맷({ext}) — 내부 LNK/스크립트 주의");
                }
            }
            else if (ScriptFileAnalyzer.IsSupportedScriptExtension(ext))
            {
                // 7B. Pre-execution static content scan for .ps1 / .bat / .cmd / .vbs / .js / .hta
                var scriptResult = ScriptFileAnalyzer.AnalyzeFile(filePath, policy);
                if (scriptResult.IsSuspicious)
                {
                    risk = Math.Max(risk, scriptResult.RiskScore);
                    reasons.AddRange(scriptResult.Reasons);
                }
            }
            else if (isZip)
            {
                // 7C. In-memory .ZIP archive inspection (no disk extraction)
                var zipResult = ZipArchiveAnalyzer.AnalyzeZipFile(filePath, policy);
                if (zipResult.IsMaliciousOrSuspicious)
                {
                    risk = Math.Max(risk, zipResult.RiskScore);
                    reasons.AddRange(zipResult.Reasons);
                }
            }

            // 8. Whitelist reduction (NEVER silence IOC hash match, tampered signature, confirmed YARA, polyglot/stego, or DLL sideloading!)
            var fullFilePath = Path.GetFullPath(filePath);
            if (policy.WhitelistedExecutablePaths.Any(w => w.Equals(fullFilePath, StringComparison.OrdinalIgnoreCase)) &&
                !_intelStore.IsHashBlocked(sha256) &&
                sig.Status != SignatureStatus.InvalidOrTampered &&
                !sigMatch.IsMatched &&
                !deepSniff.IsThreat &&
                !dllSideload.IsSideloading)
            {
                risk = Math.Min(risk, 10);
            }

            risk = Math.Clamp(risk, 0, 100);
            if (!includeClean && risk < 40)
            {
                return null;
            }

            var severity = risk >= 80
                ? ThreatSeverity.Critical
                : (risk >= 60 ? ThreatSeverity.High : (risk >= 40 ? ThreatSeverity.Medium : ThreatSeverity.Info));

            return new ScanFinding(filePath, sha256, risk, severity, sig, pe, reasons, hasMotw);
        }
        catch
        {
            return null;
        }
    }

    public Task<IReadOnlyList<ScanFinding>> ScanDirectoryAsync(
        string directory,
        GuardPolicy policy,
        IProgress<ScanProgressReport>? progress = null,
        CancellationToken ct = default)
    {
        return Task.Run<IReadOnlyList<ScanFinding>>(() =>
        {
            if (!Directory.Exists(directory))
            {
                return Array.Empty<ScanFinding>();
            }

            var files = SafeEnumerateScannableFiles(directory, maxFiles: 3000, ct);
            return ScanFileList(files, policy, progress, ct);
        }, ct);
    }

    public Task<IReadOnlyList<ScanFinding>> RunQuickScanAsync(
        GuardPolicy policy,
        IProgress<ScanProgressReport>? progress = null,
        CancellationToken ct = default)
    {
        return Task.Run<IReadOnlyList<ScanFinding>>(() =>
        {
            var targets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            var quickDirs = new[]
            {
                Path.Combine(userProfile, "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp")
            };

            foreach (var dir in quickDirs)
            {
                if (Directory.Exists(dir))
                {
                    foreach (var f in SafeEnumerateScannableFiles(dir, maxFiles: 400, ct))
                    {
                        targets.Add(f);
                    }
                }
            }

            // Include all currently running non-Windows executables
            var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    var path = _processController.GetExecutablePath(proc.Id);
                    if (!string.IsNullOrWhiteSpace(path) &&
                        File.Exists(path) &&
                        !path.StartsWith(windowsDir, StringComparison.OrdinalIgnoreCase))
                    {
                        targets.Add(path);
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }

            return ScanFileList(targets.ToList(), policy, progress, ct);
        }, ct);
    }

    private IReadOnlyList<ScanFinding> ScanFileList(
        IReadOnlyList<string> files,
        GuardPolicy policy,
        IProgress<ScanProgressReport>? progress,
        CancellationToken ct)
    {
        var findings = new ConcurrentBag<ScanFinding>();
        int scanned = 0;

        Parallel.ForEach(
            files,
            new ParallelOptions { MaxDegreeOfParallelism = Math.Max(2, Environment.ProcessorCount / 2), CancellationToken = ct },
            file =>
            {
                var finding = ScanFile(file, policy, includeClean: false);
                if (finding is not null)
                {
                    findings.Add(finding);
                }

                int count = Interlocked.Increment(ref scanned);
                if (count % 10 == 0 || count == files.Count)
                {
                    progress?.Report(new ScanProgressReport(count, findings.Count, file));
                }
            });

        return findings.OrderByDescending(f => f.RiskScore).ToList();
    }

    private static List<string> SafeEnumerateScannableFiles(string rootDir, int maxFiles, CancellationToken ct)
    {
        var list = new List<string>();
        var queue = new Queue<string>(); // BFS ensures shallow/top-level folders are never starved by deep subtrees
        var enumOpts = new EnumerationOptions
        {
            AttributesToSkip = FileAttributes.ReparsePoint, // Prevent infinite junction/symlink loops
            IgnoreInaccessible = true,
            RecurseSubdirectories = false
        };
        queue.Enqueue(rootDir);

        while (queue.Count > 0 && list.Count < maxFiles && !ct.IsCancellationRequested)
        {
            var dir = queue.Dequeue();
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", enumOpts))
                {
                    if (list.Count >= maxFiles) break;
                    var ext = Path.GetExtension(file);
                    bool scannable = ScannableExtensions.Contains(ext) ||
                                     PolyglotAndMagicSniffer.IsDeepSniffCandidate(ext);
                    if (scannable)
                    {
                        list.Add(file);
                    }
                }

                foreach (var sub in Directory.EnumerateDirectories(dir, "*", enumOpts))
                {
                    var name = Path.GetFileName(sub);
                    if (name.Equals("node_modules", StringComparison.OrdinalIgnoreCase) ||
                        name.Equals(".git", StringComparison.OrdinalIgnoreCase) ||
                        name.Equals("obj", StringComparison.OrdinalIgnoreCase) ||
                        name.Equals("Cache_Data", StringComparison.OrdinalIgnoreCase) ||
                        name.Equals("Code Cache", StringComparison.OrdinalIgnoreCase) ||
                        name.Equals("GPUCache", StringComparison.OrdinalIgnoreCase) ||
                        name.Equals("cache2", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    queue.Enqueue(sub);
                }
            }
            catch
            {
                // Skip inaccessible directories.
            }
        }

        return list;
    }
}
