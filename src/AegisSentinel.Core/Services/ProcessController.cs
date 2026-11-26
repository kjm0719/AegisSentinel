using System.Collections.Concurrent;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using AegisSentinel.Core.Models;
using AegisSentinel.Core.Native;

namespace AegisSentinel.Core.Services;

public interface IProcessNativeOperations
{
    IntPtr OpenProcess(uint desiredAccess, int pid, out int lastWin32Error);
    void CloseHandle(IntPtr handle);
    bool TryGetCreationTimeFileTimeUtc(IntPtr handle, out long creationTimeFileTimeUtc);
    bool TryGetExitCode(IntPtr handle, out uint exitCode);
    string QueryExecutablePath(IntPtr handle);
    int SuspendProcess(IntPtr handle);
    int ResumeProcess(IntPtr handle);
    bool TerminateProcess(IntPtr handle, uint exitCode);
}

internal sealed class Win32ProcessNativeOperations : IProcessNativeOperations
{
    public IntPtr OpenProcess(uint desiredAccess, int pid, out int lastWin32Error)
    {
        var handle = NativeMethods.OpenProcess(desiredAccess, false, pid);
        lastWin32Error = handle == IntPtr.Zero ? Marshal.GetLastWin32Error() : 0;
        return handle;
    }

    public void CloseHandle(IntPtr handle)
    {
        if (handle != IntPtr.Zero)
        {
            NativeMethods.CloseHandle(handle);
        }
    }

    public bool TryGetCreationTimeFileTimeUtc(IntPtr handle, out long creationTimeFileTimeUtc)
    {
        if (NativeMethods.GetProcessTimes(handle, out long creation, out _, out _, out _))
        {
            creationTimeFileTimeUtc = creation;
            return true;
        }
        creationTimeFileTimeUtc = 0;
        return false;
    }

    public bool TryGetExitCode(IntPtr handle, out uint exitCode) =>
        NativeMethods.GetExitCodeProcess(handle, out exitCode);

    public string QueryExecutablePath(IntPtr handle)
    {
        var sb = new StringBuilder(1024);
        var size = (uint)sb.Capacity;
        return NativeMethods.QueryFullProcessImageName(handle, 0, sb, ref size)
            ? sb.ToString()
            : string.Empty;
    }

    public int SuspendProcess(IntPtr handle) => NativeMethods.NtSuspendProcess(handle);

    public int ResumeProcess(IntPtr handle) => NativeMethods.NtResumeProcess(handle);

    public bool TerminateProcess(IntPtr handle, uint exitCode) => NativeMethods.TerminateProcess(handle, exitCode);
}

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

    private readonly ConcurrentDictionary<int, ProcessInstanceIdentity> _suspendedPids = new();
    private readonly Func<int, bool>? _suspendPidOverride;
    private readonly IProcessNativeOperations _nativeOps;
    private readonly bool _isDefaultWin32Ops;

    public ProcessController(
        Func<int, bool>? suspendPidOverride = null,
        IProcessNativeOperations? nativeOps = null)
    {
        _suspendPidOverride = suspendPidOverride;
        _isDefaultWin32Ops = nativeOps is null;
        _nativeOps = nativeOps ?? new Win32ProcessNativeOperations();
    }

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
            if (_isDefaultWin32Ops)
            {
                try
                {
                    using var p = Process.GetProcessById(pid);
                    if (KernelPseudoProcessNames.Contains(p.ProcessName)) return true;
                }
                catch { }
            }
            return false;
        }

        return IsCriticalProtectedPath(rawPath);
    }

    public bool IsCriticalProtectedPath(string? rawPath)
    {
        if (string.IsNullOrWhiteSpace(rawPath))
        {
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

    public IReadOnlyCollection<int> GetTrackedSuspendedPids() => _suspendedPids.Keys.ToList();

    public bool TryGetTrackedSuspendedInstance(int pid, out ProcessInstanceIdentity? instance) =>
        _suspendedPids.TryGetValue(pid, out instance);

    public bool TryGetProcessInstanceIdentity(int pid, out ProcessInstanceIdentity? identity) =>
        TryInspectProcessInstanceIdentity(pid, out identity, out _);

    public bool TryInspectProcessInstanceIdentity(
        int pid,
        out ProcessInstanceIdentity? identity,
        out ProcessIdentityVerificationStatus lookupStatus)
    {
        identity = null;
        if (pid <= 4)
        {
            lookupStatus = ProcessIdentityVerificationStatus.ExitedOrReplaced;
            return false;
        }

        var handle = _nativeOps.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, pid, out int openError);
        if (handle == IntPtr.Zero)
        {
            lookupStatus = openError == NativeMethods.ERROR_INVALID_PARAMETER
                ? ProcessIdentityVerificationStatus.ExitedOrReplaced
                : ProcessIdentityVerificationStatus.LookupFailed;
            return false;
        }

        try
        {
            if (_nativeOps.TryGetExitCode(handle, out uint exitCode) && exitCode != NativeMethods.STILL_ACTIVE)
            {
                lookupStatus = ProcessIdentityVerificationStatus.ExitedOrReplaced;
                return false;
            }
            _nativeOps.TryGetCreationTimeFileTimeUtc(handle, out long creationTimeUtc);
            var exePath = _nativeOps.QueryExecutablePath(handle);
            identity = new ProcessInstanceIdentity(pid, creationTimeUtc, exePath);
            lookupStatus = ProcessIdentityVerificationStatus.Matched;
            return true;
        }
        finally
        {
            _nativeOps.CloseHandle(handle);
        }
    }

    /// <summary>
    /// Verifies a process instance using a single query handle and distinguishes
    /// Matched, ExitedOrReplaced, and LookupFailed (never clearing tracking on LookupFailed).
    /// </summary>
    public ProcessIdentityVerificationStatus VerifyProcessInstanceIdentity(
        int pid,
        long expectedCreationTimeUtc,
        string? expectedExecutablePath = null)
    {
        if (pid <= 4)
        {
            return ProcessIdentityVerificationStatus.ExitedOrReplaced;
        }

        var handle = _nativeOps.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, pid, out int openError);
        if (handle == IntPtr.Zero)
        {
            if (openError == NativeMethods.ERROR_INVALID_PARAMETER)
            {
                RemoveTrackedIfMatching(pid, expectedCreationTimeUtc);
                return ProcessIdentityVerificationStatus.ExitedOrReplaced;
            }
            return ProcessIdentityVerificationStatus.LookupFailed;
        }

        try
        {
            if (_nativeOps.TryGetExitCode(handle, out uint exitCode) && exitCode != NativeMethods.STILL_ACTIVE)
            {
                RemoveTrackedIfMatching(pid, expectedCreationTimeUtc);
                return ProcessIdentityVerificationStatus.ExitedOrReplaced;
            }

            switch (VerifyHandleCreationTime(handle, expectedCreationTimeUtc))
            {
                case InstanceIdentityMatch.Mismatched:
                    RemoveTrackedIfMatching(pid, expectedCreationTimeUtc);
                    return ProcessIdentityVerificationStatus.ExitedOrReplaced;

                case InstanceIdentityMatch.LookupFailed:
                    return ProcessIdentityVerificationStatus.LookupFailed;
            }

            if (!string.IsNullOrWhiteSpace(expectedExecutablePath))
            {
                var livePath = _nativeOps.QueryExecutablePath(handle);
                if (string.IsNullOrWhiteSpace(livePath))
                {
                    if (expectedCreationTimeUtc == 0)
                    {
                        return ProcessIdentityVerificationStatus.LookupFailed;
                    }
                }
                else if (!livePath.Equals(expectedExecutablePath, StringComparison.OrdinalIgnoreCase))
                {
                    RemoveTrackedIfMatching(pid, expectedCreationTimeUtc);
                    return ProcessIdentityVerificationStatus.ExitedOrReplaced;
                }
            }

            return ProcessIdentityVerificationStatus.Matched;
        }
        finally
        {
            _nativeOps.CloseHandle(handle);
        }
    }

    public void ResumeAllSuspendedProcesses()
    {
        foreach (var pid in _suspendedPids.Keys.ToList())
        {
            TryResumeProcessDetailed(pid);
        }
    }

    public sealed record ProcessTreeSuspensionResult(
        int RootPid,
        bool RootSuspended,
        IReadOnlyList<int> SuspendedChildPids,
        int AttemptedChildCount,
        ProcessInstanceIdentity? RootInstance = null,
        IReadOnlyList<ProcessInstanceIdentity>? SuspendedChildInstances = null)
    {
        public int TotalSuspendedCount => (RootSuspended ? 1 : 0) + SuspendedChildPids.Count;
        public bool AnySuspended => TotalSuspendedCount > 0;
    }

    /// <summary>
    /// Suspends both the offending root process and any non-critical descendant processes
    /// it spawned, returning exact per-process results and instance identities so callers
    /// never misreport partial freezes or act on recycled PIDs later.
    /// </summary>
    public ProcessTreeSuspensionResult TrySuspendProcessTreeDetailed(int rootPid, IEnumerable<int> descendantPids)
    {
        bool rootSuspended = TrySuspendProcessDetailed(rootPid, out var rootInstance);
        var suspendedChildren = new List<int>();
        var suspendedChildInstances = new List<ProcessInstanceIdentity>();
        int attemptedChildren = 0;

        foreach (var childPid in descendantPids.Distinct())
        {
            if (childPid == rootPid || childPid <= 4) continue;
            attemptedChildren++;
            if (TrySuspendProcessDetailed(childPid, out var childInstance))
            {
                suspendedChildren.Add(childPid);
                suspendedChildInstances.Add(childInstance ?? new ProcessInstanceIdentity(childPid, 0, string.Empty));
            }
        }

        return new ProcessTreeSuspensionResult(
            rootPid,
            rootSuspended,
            suspendedChildren,
            attemptedChildren,
            rootInstance,
            suspendedChildInstances);
    }

    public int TrySuspendProcessTree(int rootPid, IEnumerable<int> descendantPids) =>
        TrySuspendProcessTreeDetailed(rootPid, descendantPids).TotalSuspendedCount;

    public ProcessTreeResumeResult TryResumeProcessTreeDetailed(
        int rootPid,
        long rootExpectedCreationTimeUtc,
        IEnumerable<ProcessInstanceIdentity>? childInstances,
        IEnumerable<int>? fallbackChildPids = null)
    {
        ProcessResumeStatus? rootStatus = null;
        if (rootPid > 4 && IsProcessSuspendedByUs(rootPid))
        {
            rootStatus = TryResumeProcessDetailed(rootPid, rootExpectedCreationTimeUtc).Status;
        }

        var childTargets = new Dictionary<int, long>();
        if (childInstances is not null)
        {
            foreach (var inst in childInstances)
            {
                if (inst.ProcessId <= 4 || inst.ProcessId == rootPid) continue;
                if (!childTargets.TryGetValue(inst.ProcessId, out var existing) || (existing == 0 && inst.CreationTimeFileTimeUtc != 0))
                {
                    childTargets[inst.ProcessId] = inst.CreationTimeFileTimeUtc;
                }
            }
        }
        if (fallbackChildPids is not null)
        {
            foreach (var childPid in fallbackChildPids)
            {
                if (childPid <= 4 || childPid == rootPid) continue;
                childTargets.TryAdd(childPid, 0);
            }
        }

        var childResults = new List<ProcessResumeItemResult>();
        foreach (var kvp in childTargets)
        {
            if (IsProcessSuspendedByUs(kvp.Key))
            {
                childResults.Add(TryResumeProcessDetailed(kvp.Key, kvp.Value));
            }
        }

        return new ProcessTreeResumeResult(rootPid, rootStatus, childResults);
    }

    public int TryResumeProcessTree(int rootPid, IEnumerable<int> descendantPids)
    {
        var result = TryResumeProcessTreeDetailed(rootPid, 0, null, descendantPids);
        int resumed = result.RootStatus == ProcessResumeStatus.Resumed ? 1 : 0;
        resumed += result.ChildResults.Count(r => r.Status == ProcessResumeStatus.Resumed);
        return resumed;
    }

    public bool TrySuspendProcessDetailed(int pid, out ProcessInstanceIdentity? instance)
    {
        instance = null;
        if (_suspendPidOverride is not null)
        {
            bool ok = _suspendPidOverride(pid);
            if (ok)
            {
                instance = new ProcessInstanceIdentity(pid, 0, string.Empty);
                _suspendedPids[pid] = instance;
            }
            return ok;
        }

        if (pid <= 4 || pid == Environment.ProcessId || InternalHelperProcessRegistry.IsInternalHelper(pid))
        {
            return false;
        }

        // Open a single handle for both identity inspection and suspension (zero TOCTOU between path/creation-time check and NtSuspendProcess).
        var handle = _nativeOps.OpenProcess(
            NativeMethods.PROCESS_SUSPEND_RESUME | NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION,
            pid,
            out _);
        if (handle == IntPtr.Zero)
        {
            return false;
        }

        try
        {
            if (_nativeOps.TryGetExitCode(handle, out uint exitCode) && exitCode != NativeMethods.STILL_ACTIVE)
            {
                return false;
            }

            var path = _nativeOps.QueryExecutablePath(handle);
            if (IsCriticalProtectedPath(path))
            {
                return false;
            }

            _nativeOps.TryGetCreationTimeFileTimeUtc(handle, out long creationTimeUtc);

            // Idempotent guard with handle-verified creation-time check: never double-suspend the same process instance,
            // while still suspending a newly spawned process if Windows recycled a dead PID.
            if (_suspendedPids.TryGetValue(pid, out var existing))
            {
                if (existing.CreationTimeFileTimeUtc != 0 && creationTimeUtc != 0 &&
                    existing.CreationTimeFileTimeUtc == creationTimeUtc)
                {
                    instance = existing;
                    return true;
                }
                _suspendedPids.TryRemove(new KeyValuePair<int, ProcessInstanceIdentity>(pid, existing));
            }

            if (_nativeOps.SuspendProcess(handle) == 0)
            {
                instance = new ProcessInstanceIdentity(pid, creationTimeUtc, path);
                _suspendedPids[pid] = instance;
                return true;
            }

            return false;
        }
        finally
        {
            _nativeOps.CloseHandle(handle);
        }
    }

    public bool TrySuspendProcess(int pid) => TrySuspendProcessDetailed(pid, out _);

    private enum InstanceIdentityMatch
    {
        Matched,
        Mismatched,
        LookupFailed
    }

    private InstanceIdentityMatch VerifyHandleCreationTime(IntPtr handle, long expectedCreationTimeUtc)
    {
        if (expectedCreationTimeUtc == 0)
        {
            return InstanceIdentityMatch.Matched;
        }

        if (!_nativeOps.TryGetCreationTimeFileTimeUtc(handle, out long liveCreationTime) || liveCreationTime == 0)
        {
            return InstanceIdentityMatch.LookupFailed;
        }

        return liveCreationTime == expectedCreationTimeUtc
            ? InstanceIdentityMatch.Matched
            : InstanceIdentityMatch.Mismatched;
    }

    public ProcessResumeItemResult TryResumeProcessDetailed(int pid, long expectedCreationTimeUtc = 0)
    {
        if (!_suspendedPids.TryGetValue(pid, out var tracked))
        {
            return new ProcessResumeItemResult(pid, ProcessResumeStatus.AlreadyExitedOrReplaced, "추적 중인 동결 상태 없음");
        }

        if (pid <= 4 || pid == Environment.ProcessId)
        {
            _suspendedPids.TryRemove(new KeyValuePair<int, ProcessInstanceIdentity>(pid, tracked));
            return new ProcessResumeItemResult(pid, ProcessResumeStatus.AlreadyExitedOrReplaced, "시스템/자체 프로세스");
        }

        long targetCreationTime = expectedCreationTimeUtc != 0
            ? expectedCreationTimeUtc
            : tracked.CreationTimeFileTimeUtc;

        var handle = _nativeOps.OpenProcess(
            NativeMethods.PROCESS_SUSPEND_RESUME | NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION,
            pid,
            out int openError);
        if (handle == IntPtr.Zero)
        {
            if (openError == NativeMethods.ERROR_INVALID_PARAMETER)
            {
                // OS confirmed this PID no longer exists.
                _suspendedPids.TryRemove(new KeyValuePair<int, ProcessInstanceIdentity>(pid, tracked));
                return new ProcessResumeItemResult(pid, ProcessResumeStatus.AlreadyExitedOrReplaced, "프로세스가 이미 종료됨");
            }

            // Keep tracking entry intact so user/orchestrator can retry resume later!
            return new ProcessResumeItemResult(
                pid,
                ProcessResumeStatus.TransientFailureRetryRequired,
                $"핸들 열기 실패(Win32={openError}) — 재시도 필요");
        }

        try
        {
            if (_nativeOps.TryGetExitCode(handle, out uint exitCode) && exitCode != NativeMethods.STILL_ACTIVE)
            {
                _suspendedPids.TryRemove(new KeyValuePair<int, ProcessInstanceIdentity>(pid, tracked));
                return new ProcessResumeItemResult(pid, ProcessResumeStatus.AlreadyExitedOrReplaced, "프로세스가 이미 종료됨");
            }

            switch (VerifyHandleCreationTime(handle, targetCreationTime))
            {
                case InstanceIdentityMatch.Mismatched:
                    // PID was recycled to a different process instance — do not resume it, and clear stale tracking.
                    _suspendedPids.TryRemove(new KeyValuePair<int, ProcessInstanceIdentity>(pid, tracked));
                    return new ProcessResumeItemResult(pid, ProcessResumeStatus.AlreadyExitedOrReplaced, "PID가 다른 프로세스로 교체됨");

                case InstanceIdentityMatch.LookupFailed:
                    // Could not read creation time — hold BOTH ResumeProcess and tracking removal until retry confirms identity!
                    return new ProcessResumeItemResult(
                        pid,
                        ProcessResumeStatus.TransientFailureRetryRequired,
                        "프로세스 생성 시각 조회 실패 — 신원 확인 불가로 재개 보류 (재시도 필요)");
            }

            int ntStatus = _nativeOps.ResumeProcess(handle);
            if (ntStatus == 0)
            {
                _suspendedPids.TryRemove(new KeyValuePair<int, ProcessInstanceIdentity>(pid, tracked));
                return new ProcessResumeItemResult(pid, ProcessResumeStatus.Resumed, "정상 재개 완료");
            }

            if (ntStatus == NativeMethods.STATUS_PROCESS_IS_TERMINATING)
            {
                _suspendedPids.TryRemove(new KeyValuePair<int, ProcessInstanceIdentity>(pid, tracked));
                return new ProcessResumeItemResult(pid, ProcessResumeStatus.AlreadyExitedOrReplaced, "프로세스 종료 진행 중");
            }

            // Transient resume failure: keep in _suspendedPids for retry.
            return new ProcessResumeItemResult(
                pid,
                ProcessResumeStatus.TransientFailureRetryRequired,
                $"재개 실패(NTSTATUS=0x{ntStatus:X8}) — 재시도 필요");
        }
        finally
        {
            _nativeOps.CloseHandle(handle);
        }
    }

    public bool TryResumeProcess(int pid) =>
        TryResumeProcessDetailed(pid).Status == ProcessResumeStatus.Resumed;

    /// <summary>
    /// Terminates a specific process instance using ONE handle for both identity verification
    /// (creation time + executable path + critical-process check) and TerminateProcess,
    /// returning structured status so lookup/termination failures never drop frozen-process tracking.
    /// </summary>
    public ProcessTerminationItemResult TryTerminateProcessInstanceDetailed(
        int pid,
        long expectedCreationTimeUtc,
        string? expectedExecutablePath = null)
    {
        if (pid <= 4 || pid == Environment.ProcessId || InternalHelperProcessRegistry.IsInternalHelper(pid))
        {
            return new ProcessTerminationItemResult(
                pid,
                ProcessTerminationStatus.ProtectedProcessSkipped,
                IsProcessSuspendedByUs(pid),
                "시스템/자체 보호 프로세스");
        }

        var handle = _nativeOps.OpenProcess(
            NativeMethods.PROCESS_TERMINATE | NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION,
            pid,
            out int openError);
        if (handle == IntPtr.Zero)
        {
            if (openError == NativeMethods.ERROR_INVALID_PARAMETER)
            {
                RemoveTrackedIfMatching(pid, expectedCreationTimeUtc);
                return new ProcessTerminationItemResult(
                    pid,
                    ProcessTerminationStatus.AlreadyExitedOrReplaced,
                    StillSuspendedByUs: false,
                    "프로세스가 이미 종료됨");
            }

            // Keep tracking entry intact so user/orchestrator can retry terminate or resume later!
            return new ProcessTerminationItemResult(
                pid,
                ProcessTerminationStatus.TransientFailureRetryRequired,
                IsProcessSuspendedByUs(pid),
                $"종료 핸들 열기 실패(Win32={openError}) — 재시도 필요");
        }

        try
        {
            if (_nativeOps.TryGetExitCode(handle, out uint exitCode) && exitCode != NativeMethods.STILL_ACTIVE)
            {
                RemoveTrackedIfMatching(pid, expectedCreationTimeUtc);
                return new ProcessTerminationItemResult(
                    pid,
                    ProcessTerminationStatus.AlreadyExitedOrReplaced,
                    StillSuspendedByUs: false,
                    "프로세스가 이미 종료됨");
            }

            var livePath = _nativeOps.QueryExecutablePath(handle);
            if (IsCriticalProtectedPath(livePath))
            {
                return new ProcessTerminationItemResult(
                    pid,
                    ProcessTerminationStatus.ProtectedProcessSkipped,
                    IsProcessSuspendedByUs(pid),
                    "보호된 Windows/보안 프로세스");
            }

            switch (VerifyHandleCreationTime(handle, expectedCreationTimeUtc))
            {
                case InstanceIdentityMatch.Mismatched:
                    // PID has been recycled to a different process instance — refuse to terminate and clear stale tracking.
                    RemoveTrackedIfMatching(pid, expectedCreationTimeUtc);
                    return new ProcessTerminationItemResult(
                        pid,
                        ProcessTerminationStatus.AlreadyExitedOrReplaced,
                        StillSuspendedByUs: false,
                        "PID가 다른 프로세스로 교체됨");

                case InstanceIdentityMatch.LookupFailed:
                    // Could not read creation time — hold BOTH TerminateProcess and tracking removal until retry confirms identity!
                    return new ProcessTerminationItemResult(
                        pid,
                        ProcessTerminationStatus.TransientFailureRetryRequired,
                        IsProcessSuspendedByUs(pid),
                        "프로세스 생성 시각 조회 실패 — 신원 확인 불가로 종료 보류 (재시도 필요)");
            }

            if (expectedCreationTimeUtc == 0 && !string.IsNullOrWhiteSpace(expectedExecutablePath))
            {
                if (string.IsNullOrWhiteSpace(livePath))
                {
                    return new ProcessTerminationItemResult(
                        pid,
                        ProcessTerminationStatus.TransientFailureRetryRequired,
                        IsProcessSuspendedByUs(pid),
                        "실행 경로 조회 실패 — 신원 확인 불가로 종료 보류 (재시도 필요)");
                }
                if (!livePath.Equals(expectedExecutablePath, StringComparison.OrdinalIgnoreCase))
                {
                    RemoveTrackedIfMatching(pid, expectedCreationTimeUtc);
                    return new ProcessTerminationItemResult(
                        pid,
                        ProcessTerminationStatus.AlreadyExitedOrReplaced,
                        StillSuspendedByUs: false,
                        "PID 실행 경로가 변경됨");
                }
            }

            if (expectedCreationTimeUtc != 0 &&
                !string.IsNullOrWhiteSpace(expectedExecutablePath) &&
                !string.IsNullOrWhiteSpace(livePath) &&
                !livePath.Equals(expectedExecutablePath, StringComparison.OrdinalIgnoreCase))
            {
                RemoveTrackedIfMatching(pid, expectedCreationTimeUtc);
                return new ProcessTerminationItemResult(
                    pid,
                    ProcessTerminationStatus.AlreadyExitedOrReplaced,
                    StillSuspendedByUs: false,
                    "PID 실행 경로가 불일치함");
            }

            bool terminated = _nativeOps.TerminateProcess(handle, 1);
            if (terminated)
            {
                RemoveTrackedIfMatching(pid, expectedCreationTimeUtc);
                return new ProcessTerminationItemResult(
                    pid,
                    ProcessTerminationStatus.Terminated,
                    StillSuspendedByUs: false,
                    "정상 종료 완료");
            }

            // TerminateProcess failed: keep tracking entry intact if still suspended!
            return new ProcessTerminationItemResult(
                pid,
                ProcessTerminationStatus.TransientFailureRetryRequired,
                IsProcessSuspendedByUs(pid),
                "TerminateProcess 호출 실패 — 재시도 필요");
        }
        finally
        {
            _nativeOps.CloseHandle(handle);
        }
    }

    public bool TryTerminateProcessInstance(int pid, long expectedCreationTimeUtc, string? expectedExecutablePath = null) =>
        TryTerminateProcessInstanceDetailed(pid, expectedCreationTimeUtc, expectedExecutablePath).Status == ProcessTerminationStatus.Terminated;

    private void RemoveTrackedIfMatching(int pid, long expectedCreationTimeUtc)
    {
        if (_suspendedPids.TryGetValue(pid, out var tracked) &&
            (expectedCreationTimeUtc == 0 || tracked.CreationTimeFileTimeUtc == 0 || tracked.CreationTimeFileTimeUtc == expectedCreationTimeUtc))
        {
            _suspendedPids.TryRemove(new KeyValuePair<int, ProcessInstanceIdentity>(pid, tracked));
        }
    }

    public bool TryTerminateProcess(int pid)
    {
        if (pid <= 4 || pid == Environment.ProcessId || InternalHelperProcessRegistry.IsInternalHelper(pid))
        {
            return false;
        }

        if (_suspendedPids.TryGetValue(pid, out var tracked) && tracked.CreationTimeFileTimeUtc != 0)
        {
            return TryTerminateProcessInstance(pid, tracked.CreationTimeFileTimeUtc, tracked.ExecutablePath);
        }

        if (!_isDefaultWin32Ops)
        {
            return TryTerminateProcessInstance(pid, 0, null);
        }

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
            // Fall back to direct Win32 TerminateProcess on a single handle
        }

        return TryTerminateProcessInstance(pid, 0, null);
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

        var handle = _nativeOps.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, pid, out _);
        if (handle != IntPtr.Zero)
        {
            try
            {
                var path = _nativeOps.QueryExecutablePath(handle);
                if (!string.IsNullOrEmpty(path))
                {
                    return path;
                }
            }
            finally
            {
                _nativeOps.CloseHandle(handle);
            }
        }

        if (_isDefaultWin32Ops)
        {
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

        return string.Empty;
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
