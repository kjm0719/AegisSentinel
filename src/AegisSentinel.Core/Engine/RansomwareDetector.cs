using System.Collections.Concurrent;
using AegisSentinel.Core.Models;

namespace AegisSentinel.Core.Engine;

public sealed class RansomwareDetector
{
    private static readonly HashSet<string> KnownRansomwareExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".locked", ".encrypted", ".enc", ".crypted", ".crypto", ".crypt",
        ".lockbit", ".akira", ".blackcat", ".conti", ".ryuk", ".cerber",
        ".zepto", ".wannacry", ".wnry", ".wncry", ".ransom", ".aes256"
    };

    private static readonly HashSet<string> BenignBulkWriterProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer", "explorer.exe", "chrome", "chrome.exe", "msedge", "msedge.exe",
        "firefox", "firefox.exe", "brave", "brave.exe", "whale", "whale.exe",
        "7z", "7z.exe", "7zfm", "7zfm.exe", "winrar", "winrar.exe", "bandizip", "bandizip.exe", "tar", "tar.exe",
        "onedrive", "onedrive.exe", "googledrivesfs", "googledrivesfs.exe", "dropbox", "dropbox.exe",
        "phoneexperiencehost", "phoneexperiencehost.exe", "photos", "photos.exe", "kakaotalk", "kakaotalk.exe",
        "git", "git.exe", "code", "code.exe", "cursor", "cursor.exe", "devenv", "devenv.exe",
        "dotnet", "dotnet.exe", "msbuild", "msbuild.exe", "vbcscompiler", "vbcscompiler.exe",
        "node", "node.exe", "bun", "bun.exe", "deno", "deno.exe", "python", "python.exe",
        "cargo", "cargo.exe", "rustc", "rustc.exe", "go", "go.exe", "robocopy", "robocopy.exe",
        "steam", "steam.exe", "epicgameslauncher", "epicgameslauncher.exe",
        "msmpeng", "msmpeng.exe", "mpcmdrun", "mpcmdrun.exe",
        "searchindexer", "searchindexer.exe", "searchprotocolhost", "searchprotocolhost.exe",
        "language_server", "language_server.exe"
    };

    private static readonly string RealExplorerPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.Windows),
        "explorer.exe");

    private readonly ConcurrentDictionary<int, Queue<(DateTimeOffset Time, string Path)>> _pidWindow = new();
    private readonly ConcurrentDictionary<int, HashSet<string>> _highEntropyFilesByPid = new();
    private readonly ConcurrentDictionary<int, DateTimeOffset> _lastAlertByPid = new();
    private readonly object _sync = new();

    public SecurityEvent? RecordFileActivity(
        int pid,
        string processName,
        string processPath,
        string targetFilePath,
        bool isRenameOrDelete,
        bool isCanaryFile,
        GuardPolicy policy,
        DateTimeOffset? nowOverride = null,
        bool checkEntropy = true)
    {
        if (!policy.EnableRansomwareShield)
        {
            return null;
        }

        if (pid == Environment.ProcessId || ProcessRuleEvaluator.IsProtectedHostIdeProcess(processPath))
        {
            return null;
        }

        // Ignore directory notifications, transient browser partial downloads, and Office temporary lock files
        if (!isCanaryFile && Directory.Exists(targetFilePath))
        {
            return null;
        }

        var fileName = Path.GetFileName(targetFilePath);
        if (fileName.StartsWith("~$", StringComparison.Ordinal) ||
            targetFilePath.EndsWith(".crdownload", StringComparison.OrdinalIgnoreCase) ||
            targetFilePath.EndsWith(".part", StringComparison.OrdinalIgnoreCase) ||
            targetFilePath.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var now = nowOverride ?? DateTimeOffset.UtcNow;

        // 1. Honeypot / Canary tampering is immediate critical ransomware signal
        if (isCanaryFile)
        {
            // Ignore manual cleanup by the user in authentic Windows Explorer (never a spoofed C:\Temp\explorer.exe!),
            // and ignore harmless metadata touches where content is still intact
            bool isTrustedSyncOrExplorer =
                ((processName.Equals("explorer", StringComparison.OrdinalIgnoreCase) || processName.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase)) &&
                 (string.IsNullOrWhiteSpace(processPath) || processPath.Equals(RealExplorerPath, StringComparison.OrdinalIgnoreCase))) ||
                ((processName.Equals("onedrive", StringComparison.OrdinalIgnoreCase) || processName.Equals("onedrive.exe", StringComparison.OrdinalIgnoreCase)) &&
                 !ProcessRuleEvaluator.IsHighRiskDropPath(processPath));
            if (isTrustedSyncOrExplorer)
            {
                return null;
            }

            if (CanaryManager.IsCanaryFileIntactOnDisk(targetFilePath))
            {
                return null;
            }

            return new SecurityEvent
            {
                Severity = ThreatSeverity.Critical,
                Category = ThreatCategory.Ransomware,
                ActionTaken = SecurityActionTaken.Logged,
                Title = "랜섬웨어 카나리(미끼) 파일 변조 탐지!",
                Description = $"보호용 카나리 파일('{Path.GetFileName(targetFilePath)}')에 대한 비인가 수정/삭제/이름변경이 감지되었습니다.",
                ProcessId = pid,
                ProcessName = processName,
                ProcessPath = processPath,
                TargetPath = targetFilePath,
                RiskScore = 100,
                RiskSignals = new List<string> { "CanaryFileTampered(+100)" }
            };
        }

        if (!string.IsNullOrWhiteSpace(processPath) &&
            policy.WhitelistedExecutablePaths.Contains(processPath, StringComparer.OrdinalIgnoreCase))
        {
            return null;
        }

        bool isBenignBulkProcess = !string.IsNullOrWhiteSpace(processName) &&
                                   BenignBulkWriterProcesses.Contains(processName) &&
                                   !ProcessRuleEvaluator.IsHighRiskDropPath(processPath);

        // 2. Known ransomware extension detection (allow git/IDE/archivers on generic .enc/.crypt developer files)
        var ext = Path.GetExtension(targetFilePath);
        if (!string.IsNullOrEmpty(ext) && KnownRansomwareExtensions.Contains(ext))
        {
            bool isGenericDevCryptoExt = ext.Equals(".enc", StringComparison.OrdinalIgnoreCase) ||
                                         ext.Equals(".crypt", StringComparison.OrdinalIgnoreCase);
            if (!(isBenignBulkProcess && isGenericDevCryptoExt))
            {
                if (CanEmitAlert(pid, now))
                {
                    return new SecurityEvent
                    {
                        Severity = ThreatSeverity.Critical,
                        Category = ThreatCategory.Ransomware,
                        ActionTaken = SecurityActionTaken.Logged,
                        Title = $"알려진 랜섬웨어 확장자({ext}) 파일 생성/변경 탐지",
                        Description = $"'{targetFilePath}' 파일이 랜섬웨어 암호화 확장자({ext})로 변경되었습니다.",
                        ProcessId = pid,
                        ProcessName = processName,
                        ProcessPath = processPath,
                        TargetPath = targetFilePath,
                        RiskScore = 95,
                        RiskSignals = new List<string> { $"KnownRansomExtension:{ext}(+95)" }
                    };
                }

                return null;
            }
        }

        // Exempt legitimate archivers, browsers, Windows Explorer, and IDEs from velocity/entropy false positives,
        // unless the binary is spoofed inside a high-risk drop/temp path (e.g. C:\Temp\7z.exe or C:\Users\Public\git.exe).
        if (isBenignBulkProcess)
        {
            return null;
        }

        // 3. Slow/Stealth Ransomware: Shannon Entropy + Magic-Header Corruption Detection (track DISTINCT encrypted files per PID!)
        if (checkEntropy && !isRenameOrDelete && File.Exists(targetFilePath))
        {
            var entropy = EntropyAnalyzer.AnalyzeFile(targetFilePath);
            if (entropy.IsLikelyEncrypted)
            {
                var set = _highEntropyFilesByPid.GetOrAdd(pid, _ => new HashSet<string>(StringComparer.OrdinalIgnoreCase));
                int hits;
                lock (_sync)
                {
                    set.Add(targetFilePath);
                    hits = set.Count;
                }
                if (hits >= 2 && CanEmitAlert(pid, now))
                {
                    return new SecurityEvent
                    {
                        Severity = ThreatSeverity.Critical,
                        Category = ThreatCategory.Ransomware,
                        ActionTaken = SecurityActionTaken.Logged,
                        Title = "엔트로피·헤더 파괴 기반 암호화(랜섬웨어) 탐지!",
                        Description = $"{entropy.Reason} | 대상: {targetFilePath} (암호화 변조 파일 {hits}개)",
                        ProcessId = pid,
                        ProcessName = string.IsNullOrWhiteSpace(processName) ? "Unknown" : processName,
                        ProcessPath = processPath,
                        TargetPath = targetFilePath,
                        RiskScore = 95,
                        RiskSignals = new List<string> { $"HighEntropyHeaderCorrupted:{entropy.ShannonEntropy:F2}(+95)" }
                    };
                }
            }
        }

        // 4. Rapid file modification / rename burst detection within 3 seconds (skip unattributed pid <= 4 noise)
        if (pid <= 4 && string.IsNullOrWhiteSpace(processPath))
        {
            return null;
        }
        if (_pidWindow.Count > 2048)
        {
            _pidWindow.Clear();
            _highEntropyFilesByPid.Clear();
        }
        var queue = _pidWindow.GetOrAdd(pid, _ => new Queue<(DateTimeOffset, string)>());
        int distinctCount;
        lock (_sync)
        {
            var cutoff = now.AddSeconds(-3);
            while (queue.Count > 0 && queue.Peek().Time < cutoff)
            {
                queue.Dequeue();
            }

            queue.Enqueue((now, targetFilePath));
            if (isRenameOrDelete)
            {
                queue.Enqueue((now, targetFilePath + "#rename"));
            }

            distinctCount = queue.Select(x => x.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        }

        if (distinctCount >= policy.RapidWriteThresholdPer3Sec && CanEmitAlert(pid, now))
        {
            return new SecurityEvent
            {
                Severity = ThreatSeverity.Critical,
                Category = ThreatCategory.Ransomware,
                ActionTaken = SecurityActionTaken.Logged,
                Title = "대량 파일 변조/암호화 행위 탐지 (랜섬웨어 의심)",
                Description = $"3초 이내에 {distinctCount}개 이상의 파일 쓰기/이름변경이 감지되었습니다. 최근 대상: {targetFilePath}",
                ProcessId = pid,
                ProcessName = string.IsNullOrWhiteSpace(processName) ? "Unknown" : processName,
                ProcessPath = processPath,
                TargetPath = targetFilePath,
                RiskScore = 90,
                RiskSignals = new List<string> { $"RapidFileModificationBurst:{distinctCount}(+90)" }
            };
        }

        return null;
    }

    private bool CanEmitAlert(int pid, DateTimeOffset now)
    {
        if (_lastAlertByPid.Count > 2048)
        {
            var cutoff = now.AddMinutes(-10);
            foreach (var kvp in _lastAlertByPid)
            {
                if (kvp.Value < cutoff) _lastAlertByPid.TryRemove(kvp.Key, out _);
            }
        }

        if (_lastAlertByPid.TryGetValue(pid, out var last) && (now - last).TotalSeconds < 5)
        {
            return false;
        }

        _lastAlertByPid[pid] = now;
        return true;
    }

    public void ClearProcess(int pid)
    {
        _pidWindow.TryRemove(pid, out _);
        _highEntropyFilesByPid.TryRemove(pid, out _);
        _lastAlertByPid.TryRemove(pid, out _);
    }
}
