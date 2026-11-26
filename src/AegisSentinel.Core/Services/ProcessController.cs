using System.Diagnostics;
using System.Management;
using System.Security.Principal;
using System.Text;
using AegisSentinel.Core.Native;

namespace AegisSentinel.Core.Services;

public sealed class ProcessController
{
    private static readonly HashSet<string> CriticalWindowsSystemBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer.exe", "dwm.exe", "csrss.exe", "lsass.exe", "lsaiso.exe", "services.exe",
        "wininit.exe", "winlogon.exe", "LogonUI.exe", "smss.exe", "svchost.exe", "sihost.exe",
        "taskmgr.exe", "taskhostw.exe", "fontdrvhost.exe", "spoolsv.exe", "SearchIndexer.exe",
        "SearchHost.exe", "SearchProtocolHost.exe", "SearchFilterHost.exe",
        "RuntimeBroker.exe", "ShellExperienceHost.exe", "StartMenuExperienceHost.exe",
        "PhoneExperienceHost.exe", "Widgets.exe", "SecHealthUI.exe", "WindowsTerminal.exe",
        "audiodg.exe", "ctfmon.exe", "TextInputHost.exe", "conhost.exe", "OpenConsole.exe",
        "WmiPrvSE.exe", "dllhost.exe", "smartscreen.exe", "TiWorker.exe", "TrustedInstaller.exe",
        "MsMpEng.exe", "NisSrv.exe", "MpCmdRun.exe", "MpDefenderCoreService.exe",
        "SecurityHealthService.exe", "SecurityHealthSystray.exe", "SecurityHealthHost.exe"
    };

    private static readonly HashSet<string> KernelPseudoProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Idle", "Registry", "Memory Compression", "Secure System", "LsaIso", "vmmem", "vmmemWSL"
    };

    private readonly System.Collections.Concurrent.ConcurrentDictionary<int, long> _suspendedPids = new();

    public static bool IsCurrentProcessElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    public bool IsCriticalProtectedProcess(int pid)
    {
        if (pid <= 4 || pid == Environment.ProcessId || InternalHelperProcessRegistry.IsInternalHelper(pid))
        {
            return true;
        }

        var rawPath = GetExecutablePath(pid);
        if (string.IsNullOrWhiteSpace(rawPath))
        {
            try
            {
                using var p = Process.GetProcessById(pid);
                if (KernelPseudoProcessNames.Contains(p.ProcessName)) return true;
            }
            catch { }
            return false;
        }

        string path;
        try { path = Path.GetFullPath(rawPath); }
        catch { return false; }

        var selfBase = AppContext.BaseDirectory.TrimEnd('\\', '/');
        if (!string.IsNullOrEmpty(selfBase) && path.StartsWith(selfBase + "\\", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (Engine.ProcessRuleEvaluator.IsProtectedHostIdeProcess(path))
        {
            return true;
        }

        var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrWhiteSpace(windowsDir)) return false;
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

        // Protect TrustedInstaller-owned Windows 11 inbox / Microsoft Store UWP packages (e.g. Phone Link, Terminal, Security UI)
        if (!string.IsNullOrEmpty(programFiles))
        {
            var winApps = Path.Combine(programFiles, "WindowsApps") + "\\";
            if (path.StartsWith(winApps, StringComparison.OrdinalIgnoreCase) &&
                (path.Contains(@"\Microsoft.", StringComparison.OrdinalIgnoreCase) ||
                 path.Contains(@"\MicrosoftWindows.", StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
        }

        var fileName = Path.GetFileName(path);
        if (!CriticalWindowsSystemBinaries.Contains(fileName))
        {
            return false;
        }

        // Never grant critical immunity to malware dropped inside world-writable C:\Windows\Temp or C:\Windows\Tasks!
        if (path.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) ||
            path.Contains(@"\Tasks\", StringComparison.OrdinalIgnoreCase) ||
            path.Contains(@"\Debug\", StringComparison.OrdinalIgnoreCase) ||
            path.Contains(@"\Tracing\", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return path.Equals(Path.Combine(windowsDir, "explorer.exe"), StringComparison.OrdinalIgnoreCase) ||
               path.StartsWith(Path.Combine(windowsDir, "System32") + "\\", StringComparison.OrdinalIgnoreCase) ||
               path.StartsWith(Path.Combine(windowsDir, "SysWOW64") + "\\", StringComparison.OrdinalIgnoreCase) ||
               path.StartsWith(Path.Combine(windowsDir, "WinSxS") + "\\", StringComparison.OrdinalIgnoreCase) ||
               path.StartsWith(Path.Combine(windowsDir, "SystemApps") + "\\", StringComparison.OrdinalIgnoreCase) ||
               path.StartsWith(Path.Combine(windowsDir, "servicing") + "\\", StringComparison.OrdinalIgnoreCase) ||
               (!string.IsNullOrEmpty(programFiles) && path.StartsWith(Path.Combine(programFiles, "WindowsApps") + "\\", StringComparison.OrdinalIgnoreCase)) ||
               (!string.IsNullOrEmpty(programFiles) && path.StartsWith(Path.Combine(programFiles, "Windows Defender") + "\\", StringComparison.OrdinalIgnoreCase)) ||
               (!string.IsNullOrEmpty(programData) && path.StartsWith(Path.Combine(programData, "Microsoft", "Windows Defender") + "\\", StringComparison.OrdinalIgnoreCase));
    }

    public bool IsProcessSuspendedByUs(int pid) => _suspendedPids.ContainsKey(pid);

    public void ResumeAllSuspendedProcesses()
    {
        foreach (var pid in _suspendedPids.Keys.ToList())
        {
            TryResumeProcess(pid);
        }
    }

    public sealed record ProcessTreeSuspensionResult(
        int RootPid,
        bool RootSuspended,
        IReadOnlyList<int> SuspendedChildPids,
        int AttemptedChildCount)
    {
        public int TotalSuspendedCount => (RootSuspended ? 1 : 0) + SuspendedChildPids.Count;
        public bool AnySuspended => TotalSuspendedCount > 0;
    }

    private readonly Func<int, bool>? _suspendPidOverride;

    public ProcessController(Func<int, bool>? suspendPidOverride = null)
    {
        _suspendPidOverride = suspendPidOverride;
    }

    /// <summary>
    /// Suspends both the offending root process and any non-critical descendant processes
    /// it spawned, returning exact per-process results so callers never misreport partial freezes.
    /// </summary>
    public ProcessTreeSuspensionResult TrySuspendProcessTreeDetailed(int rootPid, IEnumerable<int> descendantPids)
    {
        bool rootSuspended = TrySuspendProcess(rootPid);
        var suspendedChildren = new List<int>();
        int attemptedChildren = 0;

        foreach (var childPid in descendantPids.Distinct())
        {
            if (childPid == rootPid || childPid <= 4) continue;
            attemptedChildren++;
            if (TrySuspendProcess(childPid))
            {
                suspendedChildren.Add(childPid);
            }
        }

        return new ProcessTreeSuspensionResult(rootPid, rootSuspended, suspendedChildren, attemptedChildren);
    }

    public int TrySuspendProcessTree(int rootPid, IEnumerable<int> descendantPids) =>
        TrySuspendProcessTreeDetailed(rootPid, descendantPids).TotalSuspendedCount;

    public int TryResumeProcessTree(int rootPid, IEnumerable<int> descendantPids)
    {
        int resumed = 0;
        if (TryResumeProcess(rootPid))
        {
            resumed++;
        }

        foreach (var childPid in descendantPids)
        {
            if (childPid != rootPid && IsProcessSuspendedByUs(childPid) && TryResumeProcess(childPid))
            {
                resumed++;
            }
        }

        return resumed;
    }

    private static long GetProcessStartTicksSafe(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            return proc.StartTime.ToUniversalTime().Ticks;
        }
        catch
        {
            return 0;
        }
    }

    public bool TrySuspendProcess(int pid)
    {
        if (_suspendPidOverride is not null)
        {
            bool ok = _suspendPidOverride(pid);
            if (ok) _suspendedPids[pid] = 1;
            return ok;
        }

        if (IsCriticalProtectedProcess(pid))
        {
            return false;
        }

        long currentStartTicks = GetProcessStartTicksSafe(pid);
        // Idempotent guard with PID-reuse check: never double-suspend the same process instance,
        // while still suspending a newly spawned process if Windows recycled a dead PID!
        if (_suspendedPids.TryGetValue(pid, out var existingTicks))
        {
            if (existingTicks != 0 && currentStartTicks != 0 && existingTicks == currentStartTicks)
            {
                return true;
            }
            _suspendedPids.TryRemove(pid, out _);
        }

        if (!_suspendedPids.TryAdd(pid, currentStartTicks))
        {
            return true;
        }

        var handle = NativeMethods.OpenProcess(NativeMethods.PROCESS_SUSPEND_RESUME, false, pid);
        if (handle == IntPtr.Zero)
        {
            _suspendedPids.TryRemove(pid, out _);
            return false;
        }

        try
        {
            if (NativeMethods.NtSuspendProcess(handle) == 0)
            {
                return true;
            }
            _suspendedPids.TryRemove(pid, out _);
            return false;
        }
        finally
        {
            NativeMethods.CloseHandle(handle);
        }
    }

    public bool TryResumeProcess(int pid)
    {
        if (!_suspendedPids.TryRemove(pid, out var savedTicks))
        {
            return false;
        }
        if (pid <= 4 || pid == Environment.ProcessId)
        {
            return false;
        }

        long currentTicks = GetProcessStartTicksSafe(pid);
        if (savedTicks != 0 && currentTicks != 0 && savedTicks != currentTicks)
        {
            return false; // PID was recycled to a different process
        }

        var handle = NativeMethods.OpenProcess(NativeMethods.PROCESS_SUSPEND_RESUME, false, pid);
        if (handle == IntPtr.Zero)
        {
            return false;
        }

        try
        {
            return NativeMethods.NtResumeProcess(handle) == 0;
        }
        finally
        {
            NativeMethods.CloseHandle(handle);
        }
    }

    public bool TryTerminateProcess(int pid)
    {
        _suspendedPids.TryRemove(pid, out _);
        if (IsCriticalProtectedProcess(pid))
        {
            return false;
        }

        // Prefer killing the entire malicious child process tree UNLESS a critical/self/IDE process is a descendant!
        try
        {
            using var proc = Process.GetProcessById(pid);
            bool killTree = !HasAnyProtectedDescendant(pid);
            proc.Kill(entireProcessTree: killTree);
            return true;
        }
        catch
        {
            // Fall back to direct Win32 TerminateProcess
        }

        var handle = NativeMethods.OpenProcess(NativeMethods.PROCESS_TERMINATE, false, pid);
        if (handle != IntPtr.Zero)
        {
            try
            {
                return NativeMethods.TerminateProcess(handle, 1);
            }
            finally
            {
                NativeMethods.CloseHandle(handle);
            }
        }

        return false;
    }

    private bool HasAnyProtectedDescendant(int rootPid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT ProcessId, ParentProcessId FROM Win32_Process");
            using var results = searcher.Get();
            var childrenByParent = new Dictionary<int, List<int>>();
            foreach (ManagementBaseObject obj in results)
            using (obj)
            {
                int cPid = Convert.ToInt32(obj["ProcessId"] ?? 0);
                int pPid = Convert.ToInt32(obj["ParentProcessId"] ?? 0);
                if (cPid <= 4 || pPid <= 4) continue;
                if (!childrenByParent.TryGetValue(pPid, out var list))
                {
                    list = new List<int>();
                    childrenByParent[pPid] = list;
                }
                list.Add(cPid);
            }

            var queue = new Queue<int>();
            var visited = new HashSet<int> { rootPid };
            queue.Enqueue(rootPid);
            while (queue.Count > 0)
            {
                int cur = queue.Dequeue();
                if (!childrenByParent.TryGetValue(cur, out var kids)) continue;
                foreach (var k in kids)
                {
                    if (!visited.Add(k)) continue;
                    if (IsCriticalProtectedProcess(k)) return true;
                    queue.Enqueue(k);
                }
            }
        }
        catch { }

        return false;
    }

    public string GetExecutablePath(int pid)
    {
        if (pid <= 4)
        {
            return string.Empty;
        }

        var handle = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (handle != IntPtr.Zero)
        {
            try
            {
                var sb = new StringBuilder(1024);
                var size = (uint)sb.Capacity;
                if (NativeMethods.QueryFullProcessImageName(handle, 0, sb, ref size))
                {
                    return sb.ToString();
                }
            }
            finally
            {
                NativeMethods.CloseHandle(handle);
            }
        }

        try
        {
            using var proc = Process.GetProcessById(pid);
            return proc.MainModule?.FileName ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    public (int ParentPid, string CommandLine) GetWmiProcessMetadata(int pid)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT ParentProcessId, CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
            using var collection = searcher.Get();
            foreach (ManagementBaseObject obj in collection)
            using (obj)
            {
                var parentPid = obj["ParentProcessId"] is uint p ? (int)p : 0;
                var cmd = obj["CommandLine"]?.ToString() ?? string.Empty;
                return (parentPid, cmd);
            }
        }
        catch
        {
            // Ignore access denied or short-lived process exit.
        }

        return (0, string.Empty);
    }

    public string GetProcessNameSafe(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            return proc.ProcessName;
        }
        catch
        {
            return string.Empty;
        }
    }

    public static IReadOnlyList<int> GetProcessesLockingFile(string filePath)
    {
        var pids = new List<int>();
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return pids;
        }

        var sessionKey = new StringBuilder(64);
        if (NativeMethods.RmStartSession(out var handle, 0, sessionKey) != 0)
        {
            return pids;
        }

        try
        {
            if (NativeMethods.RmRegisterResources(handle, 1, new[] { filePath }, 0, null, 0, null) != 0)
            {
                return pids;
            }

            uint pnProcInfoNeeded;
            uint pnProcInfo = 0;
            uint lpdwRebootReasons = NativeMethods.RmRebootReasonNone;

            int res = NativeMethods.RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, null, ref lpdwRebootReasons);
            if (res == NativeMethods.ERROR_MORE_DATA && pnProcInfoNeeded > 0)
            {
                pnProcInfo = pnProcInfoNeeded + 4;
                var processInfo = new NativeMethods.RM_PROCESS_INFO[pnProcInfo];
                res = NativeMethods.RmGetList(handle, out pnProcInfoNeeded, ref pnProcInfo, processInfo, ref lpdwRebootReasons);
                if (res == 0)
                {
                    for (int i = 0; i < pnProcInfo; i++)
                    {
                        pids.Add(processInfo[i].Process.dwProcessId);
                    }
                }
            }
        }
        finally
        {
            _ = NativeMethods.RmEndSession(handle);
        }

        return pids;
    }
}
