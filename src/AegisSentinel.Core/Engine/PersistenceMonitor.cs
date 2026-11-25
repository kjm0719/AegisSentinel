using System.Management;
using Microsoft.Win32;
using AegisSentinel.Core.Models;
using AegisSentinel.Core.Services;

namespace AegisSentinel.Core.Engine;

/// <summary>
/// Monitors 7 Windows persistence vectors (Sysinternals Autoruns-style):
/// Run/RunOnce, Startup folders, IFEO Debugger hijacking, Winlogon Shell/Userinit,
/// Browser forced extensions, non-Microsoft Scheduled Tasks, and WMI CommandLineEventConsumer.
/// </summary>
public sealed class PersistenceMonitor : IDisposable
{
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, (DateTime LastWriteUtc, string Command)> TaskXmlCache =
        new(StringComparer.OrdinalIgnoreCase);

    private static readonly HashSet<string> PersistenceLolBins = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe"
    };

    private readonly SignatureVerifier _signatureVerifier;
    private readonly Func<GuardPolicy> _policyProvider;
    private Dictionary<string, PersistenceEntry> _baseline = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _timerSync = new();
    private Timer? _timer;
    private int _isChecking;
    private int _pollTickCount;
    private int _startGeneration;

    public event Action<SecurityEvent>? ThreatDetected;

    public PersistenceMonitor(SignatureVerifier signatureVerifier, Func<GuardPolicy> policyProvider)
    {
        _signatureVerifier = signatureVerifier;
        _policyProvider = policyProvider;
    }

    public void Start()
    {
        Stop();
        int gen;
        lock (_timerSync)
        {
            gen = ++_startGeneration;
            _pollTickCount = 0;
        }

        // Seed fast registry/startup baseline immediately (<5ms) so UI startup/policy saves never stall,
        // then complete heavy WMI/ScheduledTask baseline asynchronously before arming the periodic timer.
        _baseline = CaptureSnapshot(includeHeavyWmiAndTasks: false);
        _ = Task.Run(() =>
        {
            try
            {
                var full = CaptureSnapshot(includeHeavyWmiAndTasks: true);
                lock (_timerSync)
                {
                    if (_startGeneration != gen) return;
                    Interlocked.Exchange(ref _baseline, full);
                    _timer = new Timer(_ => PollChanges(), null, TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(15));
                }
            }
            catch { }
        });
    }

    public void Stop()
    {
        lock (_timerSync)
        {
            _startGeneration++;
            _timer?.Dispose();
            _timer = null;
        }
    }

    public IReadOnlyList<PersistenceEntry> GetFullPersistenceInventory()
    {
        var snap = CaptureSnapshot();
        var enriched = new List<PersistenceEntry>(snap.Count);
        foreach (var entry in snap.Values.OrderBy(e => e.Category).ThenBy(e => e.Name))
        {
            var sig = !string.IsNullOrWhiteSpace(entry.ExtractedExecutablePath) && File.Exists(entry.ExtractedExecutablePath)
                ? _signatureVerifier.VerifyFile(entry.ExtractedExecutablePath)
                : new SignatureInfo(SignatureStatus.Unknown, string.Empty);
            enriched.Add(entry with { Signature = sig });
        }
        return enriched;
    }

    public IReadOnlyList<SecurityEvent> DetectDiff(
        IReadOnlyDictionary<string, PersistenceEntry> previous,
        IReadOnlyDictionary<string, PersistenceEntry> current,
        GuardPolicy policy)
    {
        var events = new List<SecurityEvent>();
        if (!policy.EnablePersistenceGuard)
        {
            return events;
        }

        foreach (var kvp in current)
        {
            if (previous.TryGetValue(kvp.Key, out var oldEntry) &&
                string.Equals(oldEntry.Value, kvp.Value.Value, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var entry = kvp.Value;
            var exePath = entry.ExtractedExecutablePath;

            // Ignore AegisSentinel's own auto-start registrations
            if (entry.Name.Equals("AegisSentinelGuard", StringComparison.OrdinalIgnoreCase) ||
                entry.Name.Equals("AegisSentinelGuardElevated", StringComparison.OrdinalIgnoreCase) ||
                (!string.IsNullOrWhiteSpace(exePath) &&
                 !string.IsNullOrWhiteSpace(Environment.ProcessPath) &&
                 exePath.Equals(Environment.ProcessPath, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            if (!string.IsNullOrWhiteSpace(exePath) &&
                policy.WhitelistedExecutablePaths.Contains(exePath, StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            var sig = !string.IsNullOrWhiteSpace(exePath) && File.Exists(exePath)
                ? _signatureVerifier.VerifyFile(exePath)
                : new SignatureInfo(SignatureStatus.Unknown, string.Empty);

            bool isCriticalVector = entry.Category is "IFEO-Debugger" or "Winlogon" or "WMI-Subscription" or "Browser-Policy";
            bool isLolBinPersistence = !string.IsNullOrWhiteSpace(exePath) &&
                                       PersistenceLolBins.Contains(Path.GetFileName(exePath));
            bool isHighRisk = isCriticalVector || !sig.IsSigned || isLolBinPersistence || ProcessRuleEvaluator.IsUserWritableRiskyPath(exePath);

            // Suppress noisy Medium alerts when legitimately signed third-party apps (Chrome/Discord/Steam/KakaoTalk)
            // update their own Run/ScheduledTask entries in Program Files / AppData\Local\Programs without using LOLBins.
            if (!isHighRisk && sig.IsSigned)
            {
                continue;
            }

            int score = isCriticalVector ? 90 : (isHighRisk ? 75 : 45);

            events.Add(new SecurityEvent
            {
                Severity = score >= 85 ? ThreatSeverity.Critical : (score >= 70 ? ThreatSeverity.High : ThreatSeverity.Medium),
                Category = ThreatCategory.Persistence,
                ActionTaken = SecurityActionTaken.Logged,
                Title = oldEntry is null
                    ? $"새 지속성({entry.Category}) 항목 등록 감지"
                    : $"기존 지속성({entry.Category}) 항목 변조 감지",
                Description = $"분류: {entry.Category} | 위치: {entry.SourceLocation} | 이름: {entry.Name} | 값: {entry.Value}",
                TargetPath = $"{entry.SourceLocation}\\{entry.Name}",
                CommandLine = entry.Value,
                ProcessPath = exePath,
                RiskScore = score,
                RiskSignals = new List<string> { $"Persistence:{entry.Category}(+{score})" },
                Signature = sig
            });
        }

        return events;
    }

    public static bool TryRollbackEntry(string sourceLocation, string entryName)
    {
        try
        {
            // Normalize kernel ETW native registry paths (\REGISTRY\MACHINE\... and \REGISTRY\USER\<SID>\...)
            var normalizedLocation = sourceLocation;
            if (normalizedLocation.StartsWith(@"\REGISTRY\MACHINE\", StringComparison.OrdinalIgnoreCase))
            {
                normalizedLocation = "HKLM\\" + normalizedLocation[@"\REGISTRY\MACHINE\".Length..];
            }
            else if (normalizedLocation.StartsWith(@"\REGISTRY\USER\", StringComparison.OrdinalIgnoreCase))
            {
                var hkuSubKey = normalizedLocation[@"\REGISTRY\USER\".Length..];
                using var userKey = Registry.Users.OpenSubKey(hkuSubKey, writable: true);
                if (userKey is not null)
                {
                    userKey.DeleteValue(entryName, throwOnMissingValue: false);
                    return true;
                }
            }

            if (normalizedLocation.StartsWith("HKCU\\", StringComparison.OrdinalIgnoreCase))
            {
                var subKey = normalizedLocation[5..];
                using var key = Registry.CurrentUser.OpenSubKey(subKey, writable: true);
                if (key is not null)
                {
                    key.DeleteValue(entryName, throwOnMissingValue: false);
                    return true;
                }
            }
            else if (normalizedLocation.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase))
            {
                var subKey = normalizedLocation[5..];
                using var key = Registry.LocalMachine.OpenSubKey(subKey, writable: true);
                if (key is not null)
                {
                    // CRITICAL SAFETY GUARD: Never delete Winlogon Shell or Userinit (doing so causes a black screen on Windows login!).
                    // Instead, restore tampered Shell/Userinit values back to their clean Windows defaults, and refuse if already clean.
                    if (subKey.EndsWith(@"\Winlogon", StringComparison.OrdinalIgnoreCase))
                    {
                        if (entryName.Equals("Shell", StringComparison.OrdinalIgnoreCase))
                        {
                            var current = key.GetValue("Shell")?.ToString()?.Trim() ?? string.Empty;
                            if (current.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
                            {
                                return false; // Already clean default Windows shell
                            }
                            key.SetValue("Shell", "explorer.exe", RegistryValueKind.String);
                            return true;
                        }

                        if (entryName.Equals("Userinit", StringComparison.OrdinalIgnoreCase))
                        {
                            var expectedUserinitExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "userinit.exe");
                            var defaultUserinit = expectedUserinitExe + ",";
                            var current = key.GetValue("Userinit")?.ToString()?.Trim().TrimEnd(',') ?? string.Empty;
                            if (current.Equals(expectedUserinitExe, StringComparison.OrdinalIgnoreCase))
                            {
                                return false; // Already clean default Windows Userinit
                            }
                            key.SetValue("Userinit", defaultUserinit, RegistryValueKind.String);
                            return true;
                        }
                    }

                    key.DeleteValue(entryName, throwOnMissingValue: false);
                    return true;
                }
            }
            else if (Directory.Exists(normalizedLocation))
            {
                // If rolling back a Windows Scheduled Task, use schtasks.exe /Delete so TaskCache registry stays consistent!
                var tasksRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
                if (normalizedLocation.TrimEnd('\\').Equals(tasksRoot.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                {
                    var normalizedTask = entryName.StartsWith('\\') ? entryName : "\\" + entryName;
                    if (normalizedTask.StartsWith(@"\Microsoft\Windows\", StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }
                    var psi = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "schtasks.exe",
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };
                    psi.ArgumentList.Add("/Delete");
                    psi.ArgumentList.Add("/TN");
                    psi.ArgumentList.Add(normalizedTask);
                    psi.ArgumentList.Add("/F");
                    using var p = System.Diagnostics.Process.Start(psi);
                    if (p is not null && p.WaitForExit(10_000) && p.ExitCode == 0)
                    {
                        return true;
                    }
                    return false;
                }

                var filePath = Path.Combine(normalizedLocation, entryName);
                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                    return true;
                }
            }
        }
        catch
        {
            return false;
        }

        return false;
    }

    private void PollChanges()
    {
        if (Interlocked.Exchange(ref _isChecking, 1) == 1)
        {
            return;
        }

        try
        {
            int tick = Interlocked.Increment(ref _pollTickCount);
            bool onBattery = PowerProfileHelper.IsOnBatteryPower;
            if (onBattery && (tick & 1) == 1)
            {
                return; // On laptop battery: 30s Registry cadence, 120s WMI/ScheduledTask cadence
            }

            var policy = _policyProvider();
            bool includeHeavy = onBattery ? (tick % 8) == 0 : (tick % 4) == 0; // Heavy WMI + Scheduled Tasks every 60s (120s on battery)
            var current = CaptureSnapshot(includeHeavyWmiAndTasks: includeHeavy);
            if (!includeHeavy)
            {
                // Preserve previous heavy entries so partial polls never produce false diffs
                foreach (var kvp in _baseline)
                {
                    if ((kvp.Key.StartsWith("ScheduledTask::", StringComparison.OrdinalIgnoreCase) ||
                         kvp.Key.StartsWith("WMI::", StringComparison.OrdinalIgnoreCase)) &&
                        !current.ContainsKey(kvp.Key))
                    {
                        current[kvp.Key] = kvp.Value;
                    }
                }
            }

            var alerts = DetectDiff(_baseline, current, policy);
            _baseline = current;

            foreach (var alert in alerts)
            {
                ThreatDetected?.Invoke(alert);
            }
        }
        catch
        {
            // Ignore transient registry/WMI read errors.
        }
        finally
        {
            Interlocked.Exchange(ref _isChecking, 0);
        }
    }

    public static Dictionary<string, PersistenceEntry> CaptureSnapshot(bool includeHeavyWmiAndTasks = true)
    {
        var result = new Dictionary<string, PersistenceEntry>(StringComparer.OrdinalIgnoreCase);

        // 1. Registry Run / RunOnce (64-bit & 32-bit WOW6432Node)
        ReadRegistryKey(Registry.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\Run", "Run-HKCU", result);
        ReadRegistryKey(Registry.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce-HKCU", result);
        ReadRegistryKey(Registry.LocalMachine, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\Run", "Run-HKLM", result);
        ReadRegistryKey(Registry.LocalMachine, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce-HKLM", result);
        ReadRegistryKey(Registry.LocalMachine, "HKLM", @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "Run-HKLM32", result);
        ReadRegistryKey(Registry.LocalMachine, "HKLM", @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce-HKLM32", result);

        // 2. Startup Folders (User & Common)
        ReadStartupFolder(Environment.GetFolderPath(Environment.SpecialFolder.Startup), "Startup-User", result);
        ReadStartupFolder(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "Startup-AllUsers", result);

        // 3. Winlogon Shell / Userinit hijacking
        ReadWinlogonKeys(result);

        // 4. IFEO Debugger hijacking
        ReadIfeoDebuggers(result);

        // 5. Forced Browser Extensions Policy (Chrome / Edge)
        ReadRegistryKey(Registry.CurrentUser, "HKCU", @"Software\Policies\Google\Chrome\ExtensionInstallForcelist", "Browser-Policy", result);
        ReadRegistryKey(Registry.CurrentUser, "HKCU", @"Software\Policies\Microsoft\Edge\ExtensionInstallForcelist", "Browser-Policy", result);
        ReadRegistryKey(Registry.LocalMachine, "HKLM", @"Software\Policies\Google\Chrome\ExtensionInstallForcelist", "Browser-Policy", result);
        ReadRegistryKey(Registry.LocalMachine, "HKLM", @"Software\Policies\Microsoft\Edge\ExtensionInstallForcelist", "Browser-Policy", result);

        if (includeHeavyWmiAndTasks)
        {
            // 6. Top-level non-Microsoft Scheduled Tasks
            ReadCustomScheduledTasks(result);

            // 7. WMI CommandLineEventConsumer (Fileless APT persistence)
            ReadWmiSubscriptions(result);
        }

        return result;
    }

    private static void ReadRegistryKey(
        RegistryKey root,
        string hiveName,
        string subKeyPath,
        string category,
        Dictionary<string, PersistenceEntry> target)
    {
        try
        {
            using var key = root.OpenSubKey(subKeyPath, writable: false);
            if (key is null) return;

            var location = $"{hiveName}\\{subKeyPath}";
            foreach (var valueName in key.GetValueNames())
            {
                var raw = key.GetValue(valueName)?.ToString() ?? string.Empty;
                var exe = ExtractExecutablePath(raw);
                target[$"{location}::{valueName}"] = new PersistenceEntry(location, category, valueName, raw, exe);
            }
        }
        catch { }
    }

    private static void ReadStartupFolder(string? startupDir, string category, Dictionary<string, PersistenceEntry> target)
    {
        if (string.IsNullOrWhiteSpace(startupDir) || !Directory.Exists(startupDir)) return;
        try
        {
            foreach (var file in Directory.GetFiles(startupDir))
            {
                var name = Path.GetFileName(file);
                if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                target[$"{startupDir}\\{name}"] = new PersistenceEntry(startupDir, category, name, file, file);
            }
        }
        catch { }
    }

    private static void ReadWinlogonKeys(Dictionary<string, PersistenceEntry> target)
    {
        try
        {
            const string subKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
            using var key = Registry.LocalMachine.OpenSubKey(subKey, false);
            if (key is null) return;

            var loc = $"HKLM\\{subKey}";
            foreach (var valName in new[] { "Shell", "Userinit" })
            {
                var raw = key.GetValue(valName)?.ToString();
                if (!string.IsNullOrWhiteSpace(raw))
                {
                    target[$"{loc}::{valName}"] = new PersistenceEntry(loc, "Winlogon", valName, raw, ExtractExecutablePath(raw));
                }
            }
        }
        catch { }
    }

    private static void ReadIfeoDebuggers(Dictionary<string, PersistenceEntry> target)
    {
        try
        {
            const string baseSub = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
            using var root = Registry.LocalMachine.OpenSubKey(baseSub, false);
            if (root is null) return;

            foreach (var childName in root.GetSubKeyNames())
            {
                try
                {
                    using var sub = root.OpenSubKey(childName, false);
                    var dbg = sub?.GetValue("Debugger")?.ToString();
                    if (!string.IsNullOrWhiteSpace(dbg))
                    {
                        var loc = $"HKLM\\{baseSub}\\{childName}";
                        target[$"{loc}::Debugger"] = new PersistenceEntry(loc, "IFEO-Debugger", "Debugger", dbg, ExtractExecutablePath(dbg));
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private static void ReadCustomScheduledTasks(Dictionary<string, PersistenceEntry> target)
    {
        try
        {
            var tasksRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
            if (!Directory.Exists(tasksRoot)) return;

            var opts = new System.IO.EnumerationOptions
            {
                RecurseSubdirectories = true,
                MaxRecursionDepth = 4,
                IgnoreInaccessible = true,
                AttributesToSkip = FileAttributes.ReparsePoint
            };

            int count = 0;
            foreach (var file in Directory.EnumerateFiles(tasksRoot, "*", opts))
            {
                var relPath = Path.GetRelativePath(tasksRoot, file);
                if (relPath.StartsWith(@"Microsoft\Windows\", StringComparison.OrdinalIgnoreCase) ||
                    relPath.Equals(@"Microsoft\Windows", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (++count > 250) break;
                var cmd = TryExtractTaskXmlCommand(file);
                var exe = ExtractExecutablePath(cmd);
                target[$"ScheduledTask::{relPath}"] = new PersistenceEntry(
                    tasksRoot,
                    "Scheduled-Task",
                    relPath,
                    string.IsNullOrWhiteSpace(cmd) ? file : cmd,
                    exe);
            }
        }
        catch { }
    }

    public static string TryExtractTaskXmlCommand(string taskFilePath)
    {
        try
        {
            if (!File.Exists(taskFilePath)) return string.Empty;
            var lastWrite = File.GetLastWriteTimeUtc(taskFilePath);
            if (TaskXmlCache.TryGetValue(taskFilePath, out var cached) && cached.LastWriteUtc == lastWrite)
            {
                return cached.Command;
            }

            var xml = File.ReadAllText(taskFilePath);
            var startIdx = xml.IndexOf("<Command>", StringComparison.OrdinalIgnoreCase);
            if (startIdx < 0)
            {
                TaskXmlCache[taskFilePath] = (lastWrite, string.Empty);
                return string.Empty;
            }
            startIdx += "<Command>".Length;
            var endIdx = xml.IndexOf("</Command>", startIdx, StringComparison.OrdinalIgnoreCase);
            if (endIdx <= startIdx)
            {
                TaskXmlCache[taskFilePath] = (lastWrite, string.Empty);
                return string.Empty;
            }
            var rawCmd = System.Net.WebUtility.HtmlDecode(xml[startIdx..endIdx].Trim().Trim('"'));
            var cmd = Environment.ExpandEnvironmentVariables(rawCmd);

            // Also extract <Arguments>...</Arguments> so MZK / Persistence checks inspect scheduled task flags (e.g. -enc / -w hidden)!
            var argStart = xml.IndexOf("<Arguments>", endIdx, StringComparison.OrdinalIgnoreCase);
            string fullCmd = cmd;
            if (argStart > 0)
            {
                argStart += "<Arguments>".Length;
                var argEnd = xml.IndexOf("</Arguments>", argStart, StringComparison.OrdinalIgnoreCase);
                if (argEnd > argStart)
                {
                    var args = Environment.ExpandEnvironmentVariables(System.Net.WebUtility.HtmlDecode(xml[argStart..argEnd].Trim()));
                    if (!string.IsNullOrWhiteSpace(args))
                    {
                        fullCmd = cmd.Contains(' ') ? $"\"{cmd}\" {args}" : $"{cmd} {args}";
                    }
                }
            }

            if (TaskXmlCache.Count > 512) TaskXmlCache.Clear();
            TaskXmlCache[taskFilePath] = (lastWrite, fullCmd);
            return fullCmd;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static void ReadWmiSubscriptions(Dictionary<string, PersistenceEntry> target)
    {
        try
        {
            var scope = new ManagementScope(@"\\.\root\subscription");
            scope.Connect();
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT Name, CommandLineTemplate, ExecutablePath FROM CommandLineEventConsumer"));
            using var collection = searcher.Get();
            foreach (ManagementBaseObject obj in collection)
            using (obj)
            {
                var name = obj["Name"]?.ToString() ?? "UnknownConsumer";
                var cmd = obj["CommandLineTemplate"]?.ToString() ?? obj["ExecutablePath"]?.ToString() ?? string.Empty;
                var exe = obj["ExecutablePath"]?.ToString() ?? ExtractExecutablePath(cmd);
                target[$"WMI::CommandLineEventConsumer::{name}"] = new PersistenceEntry(
                    @"root\subscription\CommandLineEventConsumer",
                    "WMI-Subscription",
                    name,
                    cmd,
                    exe);
            }
        }
        catch
        {
            // WMI root\subscription often requires Administrator rights; ignore when non-elevated.
        }
    }

    public static string ExtractExecutablePath(string command)
    {
        if (string.IsNullOrWhiteSpace(command))
        {
            return string.Empty;
        }

        var trimmed = command.Trim();
        string candidate;
        if (trimmed.StartsWith('"'))
        {
            var endQuote = trimmed.IndexOf('"', 1);
            if (endQuote > 1)
            {
                candidate = Environment.ExpandEnvironmentVariables(trimmed[1..endQuote]);
                return ResolveRelativeSystemExecutable(candidate);
            }
        }

        var expandedWhole = Environment.ExpandEnvironmentVariables(trimmed.TrimEnd(','));
        if (Path.IsPathRooted(expandedWhole) && File.Exists(expandedWhole))
        {
            return expandedWhole;
        }

        var firstSpace = trimmed.IndexOf(' ');
        if (firstSpace > 0)
        {
            var firstToken = Environment.ExpandEnvironmentVariables(trimmed[..firstSpace].Trim().TrimEnd(','));
            if (!Path.IsPathRooted(firstToken))
            {
                var resolvedFirst = ResolveRelativeSystemExecutable(firstToken);
                if (Path.IsPathRooted(resolvedFirst))
                {
                    return resolvedFirst;
                }
            }
        }

        var exeIdx = trimmed.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exeIdx > 0)
        {
            var prefix = trimmed[..(exeIdx + 4)].Trim();
            if (!prefix.Contains("://", StringComparison.Ordinal) && !prefix.Contains('"'))
            {
                candidate = Environment.ExpandEnvironmentVariables(prefix);
                return ResolveRelativeSystemExecutable(candidate);
            }
        }

        var token = firstSpace > 0 ? trimmed[..firstSpace] : trimmed;
        candidate = Environment.ExpandEnvironmentVariables(token.Trim().TrimEnd(','));
        return ResolveRelativeSystemExecutable(candidate);
    }

    private static string ResolveRelativeSystemExecutable(string candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate) || Path.IsPathRooted(candidate))
        {
            return candidate;
        }

        var withExe = candidate.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? candidate : candidate + ".exe";
        var sys32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), withExe);
        if (File.Exists(sys32)) return sys32;

        var winDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), withExe);
        if (File.Exists(winDir)) return winDir;

        return candidate;
    }

    public void Dispose()
    {
        Stop();
    }
}
