using System.Text;
using AegisSentinel.App;
using AegisSentinel.Core.Engine;
using AegisSentinel.Core.Models;
using AegisSentinel.Core.Services;

namespace AegisSentinel.Tests;

/// <summary>
/// TDD regression tests for the 4 failure-path findings reviewed against commit 9c53643:
/// - P1-A: Quarantine restore reboot-delete cancel failure must not return Restored or delete quarantine copy
/// - P1-B: KillAndQuarantine child termination failure must preserve frozen child tracking & keep prompt open
/// - P1-C: Process creation-time lookup failure must hold both OS action and tracking deletion until retry succeeds
/// - P2: Saturated prompt queue auto-resume failure must hand off unresolved event to retry/user prompt
/// </summary>
public sealed class ContainmentFailurePathRegressionTests : IDisposable
{
    private readonly string _tempRoot;

    public ContainmentFailurePathRegressionTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), $"AegisFailPath_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempRoot);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempRoot))
            {
                foreach (var f in Directory.EnumerateFiles(_tempRoot, "*", SearchOption.AllDirectories))
                {
                    try { File.SetAttributes(f, FileAttributes.Normal); } catch { }
                }
                Directory.Delete(_tempRoot, recursive: true);
            }
        }
        catch { }
    }

    private sealed class FakeProc
    {
        public int Pid { get; init; }
        public long CreationTimeUtc { get; init; }
        public string ExecutablePath { get; init; } = string.Empty;
        public bool IsAlive { get; set; } = true;
        public bool IsSuspended { get; set; }
        public bool FailCreationTimeLookup { get; set; }
        public bool FailTerminate { get; set; }
        public int? NextQueryOpenError { get; set; }
        public int? NextTerminateOpenError { get; set; }
        public int? NextResumeNtStatus { get; set; }
        public int ResumeCalls { get; set; }
        public int TerminateCalls { get; set; }
    }

    private sealed class FailureInjectingNativeOps : IProcessNativeOperations
    {
        private readonly Dictionary<int, FakeProc> _procs = new();
        private readonly Dictionary<IntPtr, FakeProc> _handles = new();
        private long _nextHandle = 0x5000;

        public FakeProc Register(int pid, long creationTimeUtc, string path)
        {
            var p = new FakeProc { Pid = pid, CreationTimeUtc = creationTimeUtc, ExecutablePath = path };
            _procs[pid] = p;
            return p;
        }

        public IntPtr OpenProcess(uint desiredAccess, int pid, out int lastWin32Error)
        {
            if (!_procs.TryGetValue(pid, out var p))
            {
                lastWin32Error = 87;
                return IntPtr.Zero;
            }
            // PROCESS_TERMINATE = 0x0001, PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            if ((desiredAccess & 0x0001u) != 0 && p.NextTerminateOpenError is int termErr)
            {
                lastWin32Error = termErr;
                return IntPtr.Zero;
            }
            if (desiredAccess == 0x1000u && p.NextQueryOpenError is int queryErr)
            {
                lastWin32Error = queryErr;
                return IntPtr.Zero;
            }
            lastWin32Error = 0;
            var h = new IntPtr(Interlocked.Increment(ref _nextHandle));
            _handles[h] = p;
            return h;
        }

        public void CloseHandle(IntPtr handle) => _handles.Remove(handle);

        public bool TryGetCreationTimeFileTimeUtc(IntPtr handle, out long creationTimeFileTimeUtc)
        {
            if (_handles.TryGetValue(handle, out var p) && !p.FailCreationTimeLookup)
            {
                creationTimeFileTimeUtc = p.CreationTimeUtc;
                return true;
            }
            creationTimeFileTimeUtc = 0;
            return false;
        }

        public bool TryGetExitCode(IntPtr handle, out uint exitCode)
        {
            if (_handles.TryGetValue(handle, out var p))
            {
                exitCode = p.IsAlive ? 259u : 0u;
                return true;
            }
            exitCode = 0;
            return false;
        }

        public string QueryExecutablePath(IntPtr handle) =>
            _handles.TryGetValue(handle, out var p) ? p.ExecutablePath : string.Empty;

        public int SuspendProcess(IntPtr handle)
        {
            if (!_handles.TryGetValue(handle, out var p) || !p.IsAlive) return unchecked((int)0xC000010A);
            p.IsSuspended = true;
            return 0;
        }

        public int ResumeProcess(IntPtr handle)
        {
            if (!_handles.TryGetValue(handle, out var p)) return unchecked((int)0xC0000008);
            p.ResumeCalls++;
            if (p.NextResumeNtStatus is int st) return st;
            p.IsSuspended = false;
            return 0;
        }

        public bool TerminateProcess(IntPtr handle, uint exitCode)
        {
            if (!_handles.TryGetValue(handle, out var p) || !p.IsAlive) return false;
            p.TerminateCalls++;
            if (p.FailTerminate) return false;
            p.IsAlive = false;
            return true;
        }
    }

    [Fact]
    public void P1_A_RestoreFile_RebootDeleteCancelFailure_MustNotReturnRestoredAndMustPreserveCopy()
    {
        var dir = Path.Combine(_tempRoot, "p1_a_reboot_cancel");
        Directory.CreateDirectory(dir);

        var target = Path.Combine(dir, "locked_then_restored.bin");
        var payload = Encoding.UTF8.GetBytes("VALUABLE-FILE-PROTECTED-FROM-REBOOT-DELETE");
        File.WriteAllBytes(target, payload);

        // Quarantine with immediate delete failing and reboot delete scheduled
        var qmSchedule = new QuarantineManager(
            dir,
            deleteFileOverride: _ => false,
            scheduleRebootDeleteOverride: _ => true);

        var entry = qmSchedule.QuarantineFile(target, "P1-A reboot delete scheduled");
        Assert.Equal(QuarantineDisposition.ScheduledDeleteOnReboot, entry.Disposition);

        // Remove original so restore writes cleanly to destination without conflict
        File.Delete(target);

        // 1. File restores cleanly, but canceling pending reboot delete FAILS ->
        //    MUST NOT return Restored and MUST preserve quarantine copy & metadata!
        var qmCancelFails = new QuarantineManager(
            dir,
            cancelRebootDeleteOverride: _ => false,
            isRebootDeleteScheduledOverride: _ => true);

        var failedCancelResult = qmCancelFails.RestoreFileDetailed(entry.Id, overwriteExisting: false);
        Assert.Equal(QuarantineRestoreStatus.RestoredButRebootDeleteCancelFailed, failedCancelResult.Status);
        Assert.False(failedCancelResult.Success);
        Assert.True(File.Exists(target));
        Assert.Equal(payload, File.ReadAllBytes(target));
        Assert.True(File.Exists(entry.QuarantineFilePath), "Quarantine copy MUST be preserved when reboot-delete cancellation fails!");
        Assert.Contains(qmCancelFails.ListEntries(), e => e.Id == entry.Id);

        // 2. Retry once reboot-delete cancellation succeeds -> returns Restored and removes quarantine copy!
        var qmCancelSucceeds = new QuarantineManager(
            dir,
            cancelRebootDeleteOverride: _ => true,
            isRebootDeleteScheduledOverride: _ => false);

        var retryResult = qmCancelSucceeds.RestoreFileDetailed(entry.Id, overwriteExisting: true);
        Assert.Equal(QuarantineRestoreStatus.Restored, retryResult.Status);
        Assert.True(retryResult.Success);
        Assert.Equal(payload, File.ReadAllBytes(target));
        Assert.False(File.Exists(entry.QuarantineFilePath));
        Assert.DoesNotContain(qmCancelSucceeds.ListEntries(), e => e.Id == entry.Id);
    }

    [Fact]
    public void P1_B_KillAndQuarantine_ChildTerminateFailure_MustPreserveFrozenChildTrackingAndKeepPromptOpen()
    {
        var dir = Path.Combine(_tempRoot, "p1_b");
        Directory.CreateDirectory(dir);

        var parentExe = Path.Combine(dir, "dropper_parent.exe");
        File.WriteAllBytes(parentExe, Encoding.UTF8.GetBytes("FAKE-DROPPER-PAYLOAD"));

        var fake = new FailureInjectingNativeOps();
        var parent = fake.Register(71001, 133800000050010000L, parentExe);
        var child = fake.Register(71002, 133800000050020000L, Path.Combine(dir, "stuck_child.exe"));

        var procCtrl = new ProcessController(nativeOps: fake);
        var freeze = procCtrl.TrySuspendProcessTreeDetailed(71001, new[] { 71002 });
        Assert.True(freeze.RootSuspended);
        Assert.Single(freeze.SuspendedChildPids, 71002);

        // Parent terminates + file quarantines cleanly, but child termination fails!
        child.FailTerminate = true;

        var store = new PolicyStore(dir);
        using var orch = new SecurityOrchestrator(store, processController: procCtrl);
        var evt = new SecurityEvent
        {
            ProcessId = 71001,
            ProcessCreationTimeFileTimeUtc = freeze.RootInstance!.CreationTimeFileTimeUtc,
            ProcessName = "dropper_parent",
            ProcessPath = parentExe,
            Category = ThreatCategory.Ransomware,
            Severity = ThreatSeverity.Critical,
            Title = "자식 종료 실패 회귀 검증",
            ActionTaken = SecurityActionTaken.Suspended,
            IsProcessSuspended = true,
            SuspendedChildProcessIds = freeze.SuspendedChildPids.ToList(),
            SuspendedChildInstances = freeze.SuspendedChildInstances!.ToList(),
            AttemptedChildFreezeCount = 1
        };

        var killResult = orch.KillAndQuarantineDetailed(evt);

        Assert.True(killResult.RootTerminated);
        Assert.True(killResult.QuarantineRemovedOrScheduled);
        Assert.False(parent.IsAlive);
        Assert.False(File.Exists(parentExe));

        // Child 71002 failed to terminate and is STILL frozen -> tracking MUST NOT be cleared!
        Assert.True(killResult.HasAnyPendingFrozenProcess);
        Assert.False(killResult.OverallSuccess);
        Assert.Contains(71002, killResult.RemainingSuspendedChildPids);
        Assert.True(procCtrl.IsProcessSuspendedByUs(71002));
        Assert.Contains(71002, evt.SuspendedChildProcessIds);
        Assert.Contains(evt.SuspendedChildInstances, x => x.ProcessId == 71002);
        Assert.True(evt.HasAnySuspendedProcess);

        // Verify WPF ThreatPromptWindow keeps window OPEN when child termination fails, then closes once retry succeeds!
        Exception? staEx = null;
        var staThread = new Thread(() =>
        {
            try
            {
                var dispatcher = System.Windows.Threading.Dispatcher.CurrentDispatcher;
                SynchronizationContext.SetSynchronizationContext(
                    new System.Windows.Threading.DispatcherSynchronizationContext(dispatcher));

                if (System.Windows.Application.Current is null)
                {
                    var wpfApp = new AegisSentinel.App.App();
                    wpfApp.InitializeComponent();
                }

                static void RunTaskOnDispatcher(System.Windows.Threading.Dispatcher disp, Task task)
                {
                    var frame = new System.Windows.Threading.DispatcherFrame();
                    task.ContinueWith(_ => frame.Continue = false, TaskScheduler.Default);
                    System.Windows.Threading.Dispatcher.PushFrame(frame);
                    task.GetAwaiter().GetResult();
                }

                var warnings = new List<string>();
                var window = new ThreatPromptWindow(
                    orch,
                    evt,
                    queuedRemainingCount: 0,
                    messageBoxOverride: (msg, _, _, _) =>
                    {
                        warnings.Add(msg);
                        return System.Windows.MessageBoxResult.OK;
                    });
                bool closed = false;
                window.Closed += (_, _) => closed = true;
                window.ShowInTaskbar = false;
                window.Opacity = 0;
                window.Left = -10000;
                window.Top = -10000;

                try
                {
                    window.Show();

                    // First kill click while child 71002 still fails -> warning shown, window STAYS OPEN!
                    RunTaskOnDispatcher(dispatcher, window.HandleKillAndQuarantineAsync());

                    Assert.False(closed, "ThreatPromptWindow must stay open while frozen child 71002 failed termination!");
                    Assert.Single(warnings);
                    Assert.Contains("71002", warnings[0]);
                    Assert.True(procCtrl.IsProcessSuspendedByUs(71002));

                    // Now allow child 71002 termination to succeed and retry -> closes cleanly and clears tracking!
                    child.FailTerminate = false;
                    RunTaskOnDispatcher(dispatcher, window.HandleKillAndQuarantineAsync());

                    Assert.True(closed);
                    Assert.False(child.IsAlive);
                    Assert.False(procCtrl.IsProcessSuspendedByUs(71002));
                    Assert.Empty(evt.SuspendedChildProcessIds);
                    Assert.Empty(evt.SuspendedChildInstances);
                }
                finally
                {
                    if (!closed) { try { window.Close(); } catch { } }
                }
            }
            catch (Exception ex)
            {
                staEx = ex;
            }
            finally
            {
                System.Windows.Threading.Dispatcher.CurrentDispatcher.InvokeShutdown();
            }
        });
        staThread.SetApartmentState(ApartmentState.STA);
        staThread.Start();
        Assert.True(staThread.Join(TimeSpan.FromSeconds(15)));
        if (staEx is not null)
        {
            throw new Xunit.Sdk.XunitException($"WPF kill-retry STA test failed: {staEx}");
        }
    }

    [Fact]
    public void P1_C_CreationTimeLookupFailure_MustHoldBothOsActionAndTrackingUntilRetrySucceeds()
    {
        var fake = new FailureInjectingNativeOps();
        var resumeTarget = fake.Register(72001, 133800000060010000L, @"C:\Temp\resume_target.exe");
        var termTarget = fake.Register(72002, 133800000060020000L, @"C:\Temp\term_target.exe");

        var procCtrl = new ProcessController(nativeOps: fake);
        Assert.True(procCtrl.TrySuspendProcessDetailed(72001, out var instResume));
        Assert.True(procCtrl.TrySuspendProcessDetailed(72002, out var instTerm));

        // 1. Creation-time lookup fails on first attempt for BOTH resume and terminate
        resumeTarget.FailCreationTimeLookup = true;
        termTarget.FailCreationTimeLookup = true;

        var firstResume = procCtrl.TryResumeProcessDetailed(72001, instResume!.CreationTimeFileTimeUtc);
        Assert.Equal(ProcessResumeStatus.TransientFailureRetryRequired, firstResume.Status);
        Assert.Equal(0, resumeTarget.ResumeCalls);
        Assert.True(procCtrl.IsProcessSuspendedByUs(72001), "Lookup failure during resume must NOT drop tracking!");

        var firstTerm = procCtrl.TryTerminateProcessInstanceDetailed(72002, instTerm!.CreationTimeFileTimeUtc, instTerm.ExecutablePath);
        Assert.Equal(ProcessTerminationStatus.TransientFailureRetryRequired, firstTerm.Status);
        Assert.True(firstTerm.StillSuspendedByUs);
        Assert.Equal(0, termTarget.TerminateCalls);
        Assert.True(procCtrl.IsProcessSuspendedByUs(72002), "Lookup failure during terminate must NOT drop tracking!");

        // 2. Second attempt after lookup succeeds -> both complete cleanly and clear tracking!
        resumeTarget.FailCreationTimeLookup = false;
        termTarget.FailCreationTimeLookup = false;

        var secondResume = procCtrl.TryResumeProcessDetailed(72001, instResume.CreationTimeFileTimeUtc);
        Assert.Equal(ProcessResumeStatus.Resumed, secondResume.Status);
        Assert.Equal(1, resumeTarget.ResumeCalls);
        Assert.False(procCtrl.IsProcessSuspendedByUs(72001));

        var secondTerm = procCtrl.TryTerminateProcessInstanceDetailed(72002, instTerm.CreationTimeFileTimeUtc, instTerm.ExecutablePath);
        Assert.Equal(ProcessTerminationStatus.Terminated, secondTerm.Status);
        Assert.False(secondTerm.StillSuspendedByUs);
        Assert.Equal(1, termTarget.TerminateCalls);
        Assert.False(procCtrl.IsProcessSuspendedByUs(72002));
    }

    [Fact]
    public void P2_SaturatedQueue_ChildOnlyResumeFailure_MustHandOffToUserPromptAndSupportRetry()
    {
        var dir = Path.Combine(_tempRoot, "p2_saturated");
        Directory.CreateDirectory(dir);

        var fake = new FailureInjectingNativeOps();
        var frozenChild = fake.Register(83103, 133800000070010000L, Path.Combine(dir, "frozen_child.exe"));
        var procCtrl = new ProcessController(nativeOps: fake);
        var freeze = procCtrl.TrySuspendProcessTreeDetailed(83003, new[] { 83103 });
        Assert.False(freeze.RootSuspended);
        Assert.Single(freeze.SuspendedChildPids, 83103);

        // First auto-resume attempt fails transiently
        frozenChild.NextResumeNtStatus = unchecked((int)0xC0000022);

        var store = new PolicyStore(dir);
        using var orch = new SecurityOrchestrator(store, processController: procCtrl);

        var shown = new List<SecurityEvent>();
        int lastBadgeCount = 0;
        var coordinator = new ThreatPromptQueueCoordinator(
            maxQueuedPrompts: 1,
            showPrompt: e => shown.Add(e),
            updateActiveQueuedCount: c => lastBadgeCount = c,
            releaseSuspendedEvent: e => orch.AllowAndResumeProcessDetailed(e, addToWhitelist: false, grantSessionImmunity: false).AllCleared);

        var active = new SecurityEvent { ProcessId = 83001, Category = ThreatCategory.Ransomware, TargetPath = @"C:\Temp\1.doc", IsProcessSuspended = true };
        var queued = new SecurityEvent { ProcessId = 83002, Category = ThreatCategory.Ransomware, TargetPath = @"C:\Temp\2.doc", IsProcessSuspended = true };
        var saturatedChildOnly = new SecurityEvent
        {
            ProcessId = 83003,
            Category = ThreatCategory.Exfiltration,
            TargetPath = @"C:\Temp\3.bin",
            IsProcessSuspended = false,
            SuspendedChildProcessIds = freeze.SuspendedChildPids.ToList(),
            SuspendedChildInstances = freeze.SuspendedChildInstances!.ToList(),
            AttemptedChildFreezeCount = 1
        };

        coordinator.EnqueueOrShow(active);
        coordinator.EnqueueOrShow(queued);
        coordinator.EnqueueOrShow(saturatedChildOnly);

        // Queue was saturated and first auto-resume failed -> MUST be retained in UnresolvedRetryEvents!
        Assert.Single(coordinator.UnresolvedRetryEvents, saturatedChildOnly);
        Assert.Equal(2, coordinator.PendingTotalCount);
        Assert.Equal(2, lastBadgeCount);
        Assert.True(procCtrl.IsProcessSuspendedByUs(83103));
        Assert.Contains(83103, saturatedChildOnly.SuspendedChildProcessIds);

        // Closing active prompt prioritizes the unresolved failed-resume event directly to the user!
        coordinator.OnActivePromptClosed(active);
        Assert.Same(saturatedChildOnly, coordinator.ActiveEvent);
        Assert.Contains(saturatedChildOnly, shown);
        Assert.Empty(coordinator.UnresolvedRetryEvents);

        // User retries once transient error clears -> child resumes cleanly and queue proceeds to normal queued item!
        frozenChild.NextResumeNtStatus = null;
        var retryRes = orch.AllowAndResumeProcessDetailed(saturatedChildOnly, addToWhitelist: false, grantSessionImmunity: false);
        Assert.True(retryRes.AllCleared);
        Assert.False(procCtrl.IsProcessSuspendedByUs(83103));
        Assert.Empty(saturatedChildOnly.SuspendedChildProcessIds);

        coordinator.OnActivePromptClosed(saturatedChildOnly);
        Assert.Same(queued, coordinator.ActiveEvent);
    }

    [Fact]
    public void P1_StrictMode_ChildTerminateFailure_MustEmitUserInterventionRequired()
    {
        var dir = Path.Combine(_tempRoot, "p1_strict_handoff");
        Directory.CreateDirectory(dir);

        var store = new PolicyStore(dir);
        var strictPolicy = GuardPolicy.CreateDefault();
        strictPolicy.Mode = ProtectionMode.Strict;
        strictPolicy.EnableEtwTelemetry = false;
        store.Save(strictPolicy);

        var parentExe = Path.Combine(dir, "strict_parent.exe");
        File.WriteAllBytes(parentExe, Encoding.UTF8.GetBytes("STRICT-MODE-UNSIGNED-DROPPER"));

        var fake = new FailureInjectingNativeOps();
        var parent = fake.Register(74001, 133800000080010000L, parentExe);
        var child = fake.Register(74002, 133800000080020000L, Path.Combine(dir, "strict_child.exe"));
        child.FailTerminate = true;

        var procCtrl = new ProcessController(nativeOps: fake);
        using var orch = new SecurityOrchestrator(store, processController: procCtrl);
        orch.TreeTracker.RecordStart(74001, 1000, "strict_parent", parentExe, "");
        orch.TreeTracker.RecordStart(74002, 74001, "strict_child", child.ExecutablePath, "");

        var interventions = new List<SecurityEvent>();
        orch.UserInterventionRequired += e => interventions.Add(e);

        var evt = new SecurityEvent
        {
            ProcessId = 74001,
            ProcessName = "strict_parent",
            ProcessPath = parentExe,
            Category = ThreatCategory.Ransomware,
            Severity = ThreatSeverity.Critical,
            RiskScore = 95,
            Title = "엄격 모드 자식 종료 실패 회귀",
            Signature = new SignatureInfo(SignatureStatus.Unsigned, string.Empty)
        };

        orch.ProcessSecurityEvent(evt);

        Assert.False(parent.IsAlive);
        Assert.True(procCtrl.IsProcessSuspendedByUs(74002));
        var promptEvt = Assert.Single(interventions);
        Assert.Contains(74002, promptEvt.SuspendedChildProcessIds);
        Assert.True(promptEvt.HasAnySuspendedProcess);
    }

    [Fact]
    public void P1_UnfrozenChildTerminateOpenFailure_MustNotEnterFrozenListAndMustKeepProcessingEvents()
    {
        var dir = Path.Combine(_tempRoot, "p1_unfrozen_child");
        Directory.CreateDirectory(dir);

        var fake = new FailureInjectingNativeOps();
        var parent = fake.Register(75001, 133800000085010000L, Path.Combine(dir, "root_proc.exe"));
        var runningChild = fake.Register(75002, 133800000085020000L, Path.Combine(dir, "running_child.exe"));

        var procCtrl = new ProcessController(nativeOps: fake);
        // Only parent 75001 is suspended; child 75002 was NEVER suspended!
        Assert.True(procCtrl.TrySuspendProcessDetailed(75001, out var rootInst));
        Assert.False(procCtrl.IsProcessSuspendedByUs(75002));

        // Child 75002 fails terminate handle open (ERROR_ACCESS_DENIED = 5), while still running unfrozen
        runningChild.NextTerminateOpenError = 5;

        var store = new PolicyStore(dir);
        using var orch = new SecurityOrchestrator(store, processController: procCtrl);
        orch.TreeTracker.RecordStart(75001, 1000, "root_proc", parent.ExecutablePath, "");
        orch.TreeTracker.RecordStart(75002, 75001, "running_child", runningChild.ExecutablePath, "");

        var evt = new SecurityEvent
        {
            ProcessId = 75001,
            ProcessCreationTimeFileTimeUtc = rootInst!.CreationTimeFileTimeUtc,
            ProcessName = "root_proc",
            ProcessPath = parent.ExecutablePath,
            Category = ThreatCategory.Ransomware,
            Severity = ThreatSeverity.Critical,
            ActionTaken = SecurityActionTaken.Suspended,
            IsProcessSuspended = true
        };

        var res = orch.KillAndQuarantineDetailed(evt);

        Assert.True(res.RootTerminated);
        Assert.False(res.HasAnyPendingFrozenProcess);
        Assert.True(res.HasAnyTerminationRetryRequired);
        Assert.Contains(75002, res.RetryRequiredChildPids);
        Assert.Contains(75002, evt.PendingTerminationRetryChildPids);
        Assert.DoesNotContain(75002, res.RemainingSuspendedChildPids);
        Assert.DoesNotContain(75002, evt.SuspendedChildProcessIds);
        Assert.False(evt.HasAnySuspendedProcess);
        Assert.False(procCtrl.IsProcessSuspendedByUs(75002));
        Assert.Contains(res.ChildResults, r => r.ProcessId == 75002 && r.Status == ProcessTerminationStatus.TransientFailureRetryRequired && !r.StillSuspendedByUs);

        // Because running child 75002 is NOT frozen and NOT in _activeInterventionPids, its follow-up events MUST still be processed!
        var recorded = new List<SecurityEvent>();
        orch.EventRecorded += e => recorded.Add(e);
        orch.ProcessSecurityEvent(new SecurityEvent
        {
            ProcessId = 75002,
            ProcessName = "running_child",
            ProcessPath = runningChild.ExecutablePath,
            Category = ThreatCategory.CredentialAccess,
            Severity = ThreatSeverity.High,
            RiskScore = 60,
            Title = "미동결 자식 후속 악성 행위"
        });

        Assert.Contains(recorded, e => e.ProcessId == 75002);
    }

    [Fact]
    public void P1_RootIdentityAndPathLookupFailure_MustHoldTerminationAndKeepFrozenStateUntilRetry()
    {
        var dir = Path.Combine(_tempRoot, "p1_root_lookup_fail");
        Directory.CreateDirectory(dir);

        var fake = new FailureInjectingNativeOps();
        var parent = fake.Register(76001, 133800000090010000L, Path.Combine(dir, "frozen_root.exe"));
        var descendant = fake.Register(76002, 133800000090020000L, Path.Combine(dir, "live_desc.exe"));

        var procCtrl = new ProcessController(nativeOps: fake);
        Assert.True(procCtrl.TrySuspendProcessDetailed(76001, out var rootInst));
        Assert.True(procCtrl.IsProcessSuspendedByUs(76001));

        var store = new PolicyStore(dir);
        using var orch = new SecurityOrchestrator(store, processController: procCtrl);
        orch.TreeTracker.RecordStart(76001, 1000, "frozen_root", parent.ExecutablePath, "");
        orch.TreeTracker.RecordStart(76002, 76001, "live_desc", descendant.ExecutablePath, "");

        var evt = new SecurityEvent
        {
            ProcessId = 76001,
            ProcessCreationTimeFileTimeUtc = rootInst!.CreationTimeFileTimeUtc,
            ProcessName = "frozen_root",
            ProcessPath = parent.ExecutablePath,
            Category = ThreatCategory.Ransomware,
            Severity = ThreatSeverity.Critical,
            ActionTaken = SecurityActionTaken.Suspended,
            IsProcessSuspended = true
        };

        // 1. First attempt: both root identity & path query fail transiently (ERROR_ACCESS_DENIED = 5)
        parent.NextQueryOpenError = 5;

        var firstRes = orch.KillAndQuarantineDetailed(evt);
        Assert.Equal(ProcessTerminationStatus.TransientFailureRetryRequired, firstRes.RootStatus);
        Assert.True(firstRes.RootStillSuspended);
        Assert.True(firstRes.HasAnyPendingFrozenProcess);
        Assert.True(evt.IsProcessSuspended);
        Assert.True(procCtrl.IsProcessSuspendedByUs(76001));
        Assert.Equal(0, parent.TerminateCalls);
        Assert.Equal(0, descendant.TerminateCalls);

        // 2. Second attempt: lookup succeeds -> terminates both descendant and parent cleanly and clears freeze tracking!
        parent.NextQueryOpenError = null;

        var secondRes = orch.KillAndQuarantineDetailed(evt);
        Assert.True(secondRes.RootTerminated);
        Assert.Equal(ProcessTerminationStatus.Terminated, secondRes.RootStatus);
        Assert.False(secondRes.RootStillSuspended);
        Assert.False(secondRes.HasAnyPendingFrozenProcess);
        Assert.False(evt.IsProcessSuspended);
        Assert.False(parent.IsAlive);
        Assert.False(descendant.IsAlive);
        Assert.False(procCtrl.IsProcessSuspendedByUs(76001));
    }
}
