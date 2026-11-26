using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using AegisSentinel.App;
using AegisSentinel.Core.Engine;
using AegisSentinel.Core.Models;
using AegisSentinel.Core.Services;

namespace AegisSentinel.Tests;

/// <summary>
/// Deterministic regression test suite for P1-1..P1-5 and P2-1 based on main commit acbc7de.
/// Uses fake Win32 process handles and isolated temp directories so no real OS processes or user files are touched.
/// </summary>
public sealed class ContainmentSafetyRegressionTests : IDisposable
{
    private readonly string _tempRoot;

    public ContainmentSafetyRegressionTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), $"AegisP1P2_{Guid.NewGuid():N}");
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

    private sealed class FakeProcessRecord
    {
        public int Pid { get; init; }
        public long CreationTimeUtc { get; init; }
        public string ExecutablePath { get; init; } = string.Empty;
        public bool IsAlive { get; set; } = true;
        public bool IsSuspended { get; set; }
        public int? NextResumeNtStatus { get; set; }
        public int? NextOpenError { get; set; }
        public int TerminateCount { get; set; }
    }

    private sealed class FakeProcessNativeOperations : IProcessNativeOperations
    {
        private readonly Dictionary<int, FakeProcessRecord> _liveByPid = new();
        private readonly Dictionary<IntPtr, (FakeProcessRecord Record, uint Access, bool CreationTimeChecked)> _openHandles = new();
        private long _nextHandle = 0x1000;

        public List<(int Pid, long CreationTimeUtc, bool CheckedOnSameHandle)> TerminateInvocations { get; } = new();

        public FakeProcessRecord RegisterProcess(int pid, long creationTimeUtc, string executablePath)
        {
            var rec = new FakeProcessRecord
            {
                Pid = pid,
                CreationTimeUtc = creationTimeUtc,
                ExecutablePath = executablePath,
                IsAlive = true
            };
            _liveByPid[pid] = rec;
            return rec;
        }

        public void RemoveProcess(int pid) => _liveByPid.Remove(pid);

        public IntPtr OpenProcess(uint desiredAccess, int pid, out int lastWin32Error)
        {
            if (!_liveByPid.TryGetValue(pid, out var rec))
            {
                lastWin32Error = 87; // ERROR_INVALID_PARAMETER
                return IntPtr.Zero;
            }

            if (rec.NextOpenError is int err)
            {
                lastWin32Error = err;
                return IntPtr.Zero;
            }

            lastWin32Error = 0;
            var handle = new IntPtr(Interlocked.Increment(ref _nextHandle));
            _openHandles[handle] = (rec, desiredAccess, false);
            return handle;
        }

        public void CloseHandle(IntPtr handle) => _openHandles.Remove(handle);

        public bool TryGetCreationTimeFileTimeUtc(IntPtr handle, out long creationTimeFileTimeUtc)
        {
            if (_openHandles.TryGetValue(handle, out var entry))
            {
                _openHandles[handle] = (entry.Record, entry.Access, true);
                creationTimeFileTimeUtc = entry.Record.CreationTimeUtc;
                return true;
            }
            creationTimeFileTimeUtc = 0;
            return false;
        }

        public bool TryGetExitCode(IntPtr handle, out uint exitCode)
        {
            if (_openHandles.TryGetValue(handle, out var entry))
            {
                exitCode = entry.Record.IsAlive ? 259u : 0u; // STILL_ACTIVE = 259
                return true;
            }
            exitCode = 0;
            return false;
        }

        public string QueryExecutablePath(IntPtr handle) =>
            _openHandles.TryGetValue(handle, out var entry) ? entry.Record.ExecutablePath : string.Empty;

        public int SuspendProcess(IntPtr handle)
        {
            if (!_openHandles.TryGetValue(handle, out var entry) || !entry.Record.IsAlive)
            {
                return unchecked((int)0xC000010A);
            }
            entry.Record.IsSuspended = true;
            return 0;
        }

        public int ResumeProcess(IntPtr handle)
        {
            if (!_openHandles.TryGetValue(handle, out var entry))
            {
                return unchecked((int)0xC0000008);
            }
            if (!entry.Record.IsAlive)
            {
                return unchecked((int)0xC000010A);
            }
            if (entry.Record.NextResumeNtStatus is int status)
            {
                return status;
            }
            entry.Record.IsSuspended = false;
            return 0;
        }

        public bool TerminateProcess(IntPtr handle, uint exitCode)
        {
            if (!_openHandles.TryGetValue(handle, out var entry) || !entry.Record.IsAlive)
            {
                return false;
            }
            entry.Record.IsAlive = false;
            entry.Record.TerminateCount++;
            TerminateInvocations.Add((entry.Record.Pid, entry.Record.CreationTimeUtc, entry.CreationTimeChecked));
            return true;
        }
    }

    [Fact]
    public void P1_1_KillAndQuarantine_DoesNotTerminateRecycledChildPidWithDifferentStartTime()
    {
        var dir = Path.Combine(_tempRoot, "p1_1");
        Directory.CreateDirectory(dir);

        var fakeNative = new FakeProcessNativeOperations();
        var parentRec = fakeNative.RegisterProcess(70001, 133800000010000000L, Path.Combine(dir, "dropper_parent.exe"));
        _ = fakeNative.RegisterProcess(70002, 133800000010050000L, Path.Combine(dir, "old_child.exe"));
        var validChildRec = fakeNative.RegisterProcess(70003, 133800000010080000L, Path.Combine(dir, "still_frozen_child.exe"));

        var procCtrl = new ProcessController(nativeOps: fakeNative);
        var freeze = procCtrl.TrySuspendProcessTreeDetailed(70001, new[] { 70002, 70003 });

        Assert.True(freeze.RootSuspended);
        Assert.Equal(2, freeze.SuspendedChildPids.Count);
        Assert.NotNull(freeze.RootInstance);
        Assert.NotNull(freeze.SuspendedChildInstances);
        Assert.Equal(2, freeze.SuspendedChildInstances!.Count);

        // Simulate child PID 70002 exiting and Windows recycling PID 70002 to an unrelated process with a newer creation time.
        var recycledUnrelatedRec = fakeNative.RegisterProcess(70002, 133800000099990000L, Path.Combine(dir, "unrelated_editor.exe"));

        var store = new PolicyStore(dir);
        using var orch = new SecurityOrchestrator(store, processController: procCtrl);

        var evt = new SecurityEvent
        {
            ProcessId = 70001,
            ProcessCreationTimeFileTimeUtc = freeze.RootInstance!.CreationTimeFileTimeUtc,
            ProcessName = "dropper_parent",
            ProcessPath = parentRec.ExecutablePath,
            Category = ThreatCategory.Ransomware,
            Severity = ThreatSeverity.Critical,
            ActionTaken = SecurityActionTaken.Suspended,
            IsProcessSuspended = true,
            SuspendedChildProcessIds = freeze.SuspendedChildPids.ToList(),
            SuspendedChildInstances = freeze.SuspendedChildInstances.ToList(),
            AttemptedChildFreezeCount = freeze.AttemptedChildCount
        };

        bool ok = orch.KillAndQuarantine(evt);
        Assert.True(ok);

        // Recycled PID 70002 (different start time) MUST receive ZERO terminate calls and stay alive!
        Assert.Equal(0, recycledUnrelatedRec.TerminateCount);
        Assert.True(recycledUnrelatedRec.IsAlive);

        // Original matching parent and still-matching child MUST be terminated via the SAME handle used for creation-time check!
        Assert.Equal(1, parentRec.TerminateCount);
        Assert.Equal(1, validChildRec.TerminateCount);
        Assert.DoesNotContain(fakeNative.TerminateInvocations, t => t.Pid == 70002 && t.CreationTimeUtc == recycledUnrelatedRec.CreationTimeUtc);
        Assert.All(fakeNative.TerminateInvocations, t => Assert.True(t.CheckedOnSameHandle, "TerminateProcess must verify creation time on the SAME handle!"));
    }

    [Fact]
    public void P1_2_PromptQueue_HandlesChildOnlySuspensionOnSaturationDuplicateAndShutdown()
    {
        var shown = new List<SecurityEvent>();
        var released = new List<SecurityEvent>();
        int lastQueueCount = -1;

        var coordinator = new ThreatPromptQueueCoordinator(
            maxQueuedPrompts: 1,
            showPrompt: e => shown.Add(e),
            updateActiveQueuedCount: c => lastQueueCount = c,
            releaseSuspendedEvent: e => released.Add(e));

        // 1. Active prompt (root 80001 suspended) + 1 queued prompt (root 80002, child-only 81004 suspended) -> queue is now FULL
        var activeEvt = new SecurityEvent
        {
            ProcessId = 80001,
            Category = ThreatCategory.Ransomware,
            TargetPath = @"C:\Temp\a.doc",
            IsProcessSuspended = true,
            SuspendedChildProcessIds = new List<int> { 81000 }
        };
        var queuedChildOnlyEvt = new SecurityEvent
        {
            ProcessId = 80002,
            Category = ThreatCategory.CredentialAccess,
            TargetPath = @"C:\Temp\b.dat",
            IsProcessSuspended = false,
            SuspendedChildProcessIds = new List<int> { 81004 },
            AttemptedChildFreezeCount = 1
        };

        coordinator.EnqueueOrShow(activeEvt);
        coordinator.EnqueueOrShow(queuedChildOnlyEvt);
        Assert.Single(shown);
        Assert.Equal(1, coordinator.QueuedCount);
        Assert.Equal(1, lastQueueCount);
        Assert.Empty(released);

        // 2. Duplicate prompt for activeEvt carrying a newly frozen child 81003:
        //    MUST hand over 81003 to activeEvt WITHOUT prematurely releasing activeEvt's processes!
        var dupActiveEvt = new SecurityEvent
        {
            ProcessId = 80001,
            Category = ThreatCategory.Ransomware,
            TargetPath = @"C:\Temp\a.doc",
            IsProcessSuspended = false,
            SuspendedChildProcessIds = new List<int> { 81003 },
            SuspendedChildInstances = new List<ProcessInstanceIdentity> { new(81003, 55555L, @"C:\Temp\c3.exe") }
        };
        coordinator.EnqueueOrShow(dupActiveEvt);
        Assert.Empty(released);
        Assert.Contains(81003, activeEvt.SuspendedChildProcessIds);
        Assert.Contains(activeEvt.SuspendedChildInstances, x => x.ProcessId == 81003 && x.CreationTimeFileTimeUtc == 55555L);

        // 3. Queue saturated: child-only suspended event for SAME root 80001 (different category/target) -> handed over to activeEvt!
        var saturatedSameRootChildOnly = new SecurityEvent
        {
            ProcessId = 80001,
            Category = ThreatCategory.NetworkAnomaly,
            TargetPath = @"C:\Temp\c.net",
            IsProcessSuspended = false,
            SuspendedChildProcessIds = new List<int> { 81002 }
        };
        coordinator.EnqueueOrShow(saturatedSameRootChildOnly);
        Assert.Empty(released);
        Assert.Contains(81002, activeEvt.SuspendedChildProcessIds);

        // 4. Queue saturated: child-only suspended event for UNRELATED root 80099 -> MUST be released (never silently dropped)!
        var saturatedUnrelatedChildOnly = new SecurityEvent
        {
            ProcessId = 80099,
            Category = ThreatCategory.Exfiltration,
            TargetPath = @"C:\Temp\d.bin",
            IsProcessSuspended = false,
            SuspendedChildProcessIds = new List<int> { 81001 },
            AttemptedChildFreezeCount = 1
        };
        Assert.True(saturatedUnrelatedChildOnly.HasAnySuspendedProcess);
        coordinator.EnqueueOrShow(saturatedUnrelatedChildOnly);
        Assert.Contains(saturatedUnrelatedChildOnly, released);

        // 5. Shutdown drain: queuedChildOnlyEvt (parent running, child 81004 frozen) MUST also be released!
        coordinator.DrainAllQueued();
        Assert.Equal(0, coordinator.QueuedCount);
        Assert.Contains(queuedChildOnlyEvt, released);
    }

    [Fact]
    public void P1_3_ResumeFailure_MustKeepFailedChildTrackedUntilRetrySucceeds()
    {
        var dir = Path.Combine(_tempRoot, "p1_3");
        Directory.CreateDirectory(dir);

        var fakeNative = new FakeProcessNativeOperations();
        var child1 = fakeNative.RegisterProcess(91001, 133800000020010000L, Path.Combine(dir, "child1.exe"));
        var child2 = fakeNative.RegisterProcess(91002, 133800000020020000L, Path.Combine(dir, "child2.exe"));
        var exitedChild = fakeNative.RegisterProcess(91003, 133800000020030000L, Path.Combine(dir, "child3.exe"));

        var procCtrl = new ProcessController(nativeOps: fakeNative);
        // Parent 91000 is not registered (fails freeze), children 91001, 91002, 91003 freeze
        var freeze = procCtrl.TrySuspendProcessTreeDetailed(91000, new[] { 91001, 91002, 91003 });
        Assert.False(freeze.RootSuspended);
        Assert.Equal(3, freeze.SuspendedChildPids.Count);
        Assert.True(procCtrl.IsProcessSuspendedByUs(91001));
        Assert.True(procCtrl.IsProcessSuspendedByUs(91002));
        Assert.True(procCtrl.IsProcessSuspendedByUs(91003));

        // Child 1 resumes normally; Child 2 fails transiently (STATUS_ACCESS_DENIED); Child 3 already exited before resume.
        child2.NextResumeNtStatus = unchecked((int)0xC0000022);
        fakeNative.RemoveProcess(91003);

        var store = new PolicyStore(dir);
        using var orch = new SecurityOrchestrator(store, processController: procCtrl);
        var evt = new SecurityEvent
        {
            ProcessId = 91000,
            ProcessName = "parent_test",
            Category = ThreatCategory.Ransomware,
            Severity = ThreatSeverity.Critical,
            ActionTaken = SecurityActionTaken.Suspended,
            IsProcessSuspended = false,
            SuspendedChildProcessIds = freeze.SuspendedChildPids.ToList(),
            SuspendedChildInstances = freeze.SuspendedChildInstances!.ToList(),
            AttemptedChildFreezeCount = 3
        };

        // First attempt: partial success -> ONLY failed child 91002 remains tracked; ActionTaken = PartiallyAllowed!
        var firstAttempt = orch.AllowAndResumeProcessDetailed(evt, addToWhitelist: false, grantSessionImmunity: false);
        Assert.False(firstAttempt.AllCleared);
        Assert.True(firstAttempt.HasAnyPendingRetry);
        Assert.True(firstAttempt.AnyResumed);
        Assert.Equal(ProcessResumeStatus.Resumed, firstAttempt.ChildResults.Single(r => r.ProcessId == 91001).Status);
        Assert.Equal(ProcessResumeStatus.TransientFailureRetryRequired, firstAttempt.ChildResults.Single(r => r.ProcessId == 91002).Status);
        Assert.Equal(ProcessResumeStatus.AlreadyExitedOrReplaced, firstAttempt.ChildResults.Single(r => r.ProcessId == 91003).Status);

        Assert.False(procCtrl.IsProcessSuspendedByUs(91001));
        Assert.True(procCtrl.IsProcessSuspendedByUs(91002));
        Assert.False(procCtrl.IsProcessSuspendedByUs(91003));
        Assert.Equal(new[] { 91002 }, evt.SuspendedChildProcessIds);
        Assert.Single(evt.SuspendedChildInstances, x => x.ProcessId == 91002);
        Assert.Equal(SecurityActionTaken.PartiallyAllowed, evt.ActionTaken);

        var auditAfterFirst = orch.AuditLog.LoadRecentEvents(10);
        Assert.Contains(auditAfterFirst, e => e.ActionTaken == SecurityActionTaken.PartiallyAllowed);

        // Second attempt after transient failure clears -> child 91002 resumes and tracking becomes completely empty!
        child2.NextResumeNtStatus = null;
        var secondAttempt = orch.AllowAndResumeProcessDetailed(evt, addToWhitelist: false, grantSessionImmunity: false);
        Assert.True(secondAttempt.AllCleared);
        Assert.False(secondAttempt.HasAnyPendingRetry);
        Assert.True(secondAttempt.AnyResumed);
        Assert.False(procCtrl.IsProcessSuspendedByUs(91002));
        Assert.Empty(procCtrl.GetTrackedSuspendedPids());
        Assert.Empty(evt.SuspendedChildProcessIds);
        Assert.Empty(evt.SuspendedChildInstances);
        Assert.Equal(SecurityActionTaken.Allowed, evt.ActionTaken);
    }

    [Fact]
    public void P1_4_QuarantineFile_MustPersistMetadataBeforeDeletingOriginalAndRecoverAfterCrash()
    {
        // Case A: Metadata must already be persisted on disk before delete runs.
        var dirA = Path.Combine(_tempRoot, "p1_4_order");
        Directory.CreateDirectory(dirA);
        var targetA = Path.Combine(dirA, "sample_dropper.exe");
        var payloadA = Encoding.UTF8.GetBytes("QUARANTINE-METADATA-ORDER-TEST-PAYLOAD");
        File.WriteAllBytes(targetA, payloadA);

        bool metadataExistedAtDeleteMoment = false;
        QuarantineManager? qmRefA = null;
        var qmA = new QuarantineManager(
            dirA,
            deleteFileOverride: path =>
            {
                metadataExistedAtDeleteMoment = Directory.GetFiles(qmRefA!.QuarantineDirectory, "*.json").Length > 0;
                File.Delete(path);
                return true;
            });
        qmRefA = qmA;

        var entryA = qmA.QuarantineFile(targetA, "P1-4 order check");
        Assert.True(metadataExistedAtDeleteMoment, "Restore metadata JSON must be safely persisted BEFORE deleting original file!");
        Assert.False(File.Exists(targetA));
        Assert.Contains(qmA.ListEntries(), e => e.Id == entryA.Id);

        // Case B: Metadata write failure MUST preserve original file AND never schedule reboot deletion!
        var dirB = Path.Combine(_tempRoot, "p1_4_meta_fail");
        Directory.CreateDirectory(dirB);
        var targetB = Path.Combine(dirB, "important_original.bin");
        var payloadB = Encoding.UTF8.GetBytes("DO-NOT-DELETE-IF-METADATA-FAILS");
        File.WriteAllBytes(targetB, payloadB);

        int deleteInvocations = 0;
        int rebootScheduleInvocations = 0;
        var qmB = new QuarantineManager(
            dirB,
            deleteFileOverride: _ => { deleteInvocations++; return true; },
            scheduleRebootDeleteOverride: _ => { rebootScheduleInvocations++; return true; },
            writeMetadataOverride: (_, _) => throw new IOException("Simulated disk full during metadata commit"));

        Assert.Throws<IOException>(() => qmB.QuarantineFile(targetB, "P1-4 meta failure"));
        Assert.True(File.Exists(targetB), "Original file must remain untouched when metadata write fails!");
        Assert.Equal(payloadB, File.ReadAllBytes(targetB));
        Assert.Equal(0, deleteInvocations);
        Assert.Equal(0, rebootScheduleInvocations);
        Assert.Empty(Directory.GetFiles(qmB.QuarantineDirectory, "*.aegisq"));

        // Case C: Crash right after deleting original (before final disposition metadata update):
        //         Restarting QuarantineManager MUST find the entry via PendingOriginalRemoval reconciliation and restore it!
        var dirC = Path.Combine(_tempRoot, "p1_4_crash_recovery");
        Directory.CreateDirectory(dirC);
        var targetC = Path.Combine(dirC, "crash_recoverable.bin");
        var payloadC = Encoding.UTF8.GetBytes("CRASH-RECOVERY-PAYLOAD-1234567890");
        File.WriteAllBytes(targetC, payloadC);

        int metaWriteCount = 0;
        var qmC = new QuarantineManager(
            dirC,
            deleteFileOverride: path =>
            {
                File.Delete(path);
                return true;
            },
            writeMetadataOverride: (metaPath, json) =>
            {
                metaWriteCount++;
                if (metaWriteCount == 1)
                {
                    File.WriteAllText(metaPath, json); // Commit initial PendingOriginalRemoval metadata
                    return;
                }
                throw new IOException("Simulated crash right after original deletion");
            });

        var entryC = qmC.QuarantineFile(targetC, "P1-4 crash recovery");
        Assert.False(File.Exists(targetC));

        // Simulate app restart with a brand new QuarantineManager instance
        var restartedQm = new QuarantineManager(dirC);
        var entriesAfterRestart = restartedQm.ListEntries();
        var recoveredEntry = Assert.Single(entriesAfterRestart, e => e.Id == entryC.Id);
        Assert.Equal(QuarantineDisposition.RemovedImmediately, recoveredEntry.Disposition);

        var restoreRes = restartedQm.RestoreFileDetailed(recoveredEntry.Id);
        Assert.True(restoreRes.Success);
        Assert.True(File.Exists(targetC));
        Assert.Equal(payloadC, File.ReadAllBytes(targetC));
    }

    [Fact]
    public void P1_5_RestoreFile_MustDetectDestinationConflictAndPreserveExistingFileOnWriteFailure()
    {
        var dir = Path.Combine(_tempRoot, "p1_5");
        Directory.CreateDirectory(dir);

        var target = Path.Combine(dir, "user_doc.bin");
        var originalBytes = Encoding.UTF8.GetBytes("ORIGINAL-QUARANTINED-BYTES-ABC123");
        File.WriteAllBytes(target, originalBytes);

        var qm = new QuarantineManager(dir);
        var entry = qm.QuarantineFile(target, "P1-5 conflict & atomic restore test");
        Assert.False(File.Exists(target));

        // User created a brand new file at the original path after quarantine
        var newUserBytes = Encoding.UTF8.GetBytes("BRAND-NEW-USER-FILE-DO-NOT-CLOBBER-XYZ987");
        File.WriteAllBytes(target, newUserBytes);
        var expectedUserHash = Convert.ToHexString(SHA256.HashData(newUserBytes));

        // 1. Default restore (overwriteExisting=false) MUST report DestinationConflict without modifying existing file or deleting quarantine copy
        var conflictResult = qm.RestoreFileDetailed(entry.Id, overwriteExisting: false);
        Assert.Equal(QuarantineRestoreStatus.DestinationConflict, conflictResult.Status);
        Assert.False(conflictResult.Success);
        Assert.Equal(expectedUserHash, Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(target))));
        Assert.True(File.Exists(entry.QuarantineFilePath), "Quarantine copy must remain intact on conflict!");

        // 2. Explicit overwrite with injected disk write failure mid-write MUST leave existing destination SHA-256 unchanged and keep quarantine copy!
        var failingQm = new QuarantineManager(
            dir,
            writeRestoreTempOverride: (tmpPath, plain) =>
            {
                File.WriteAllBytes(tmpPath, plain.Take(4).ToArray()); // Partial truncated write to temp file
                throw new IOException("Simulated disk full mid-restore");
            });

        var failedResult = failingQm.RestoreFileDetailed(entry.Id, overwriteExisting: true);
        Assert.Equal(QuarantineRestoreStatus.WriteFailed, failedResult.Status);
        Assert.False(failedResult.Success);
        Assert.Equal(expectedUserHash, Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(target))));
        Assert.True(File.Exists(entry.QuarantineFilePath), "Quarantine copy must remain intact after write failure for retry!");
        Assert.Empty(Directory.GetFiles(dir, "*.tmp"));

        // 3. Clean retry with overwriteExisting=true MUST replace destination atomically with exact quarantined bytes!
        var retryResult = qm.RestoreFileDetailed(entry.Id, overwriteExisting: true);
        Assert.Equal(QuarantineRestoreStatus.Restored, retryResult.Status);
        Assert.True(retryResult.Success);
        Assert.Equal(originalBytes, File.ReadAllBytes(target));
        Assert.False(File.Exists(entry.QuarantineFilePath));
    }

    [Fact]
    public void P2_1_AuditLog_PreservesLegacyEnumNumbers4_5_6_AndWritesSchemaVersion()
    {
        var dir = Path.Combine(_tempRoot, "p2_1");
        Directory.CreateDirectory(dir);
        var audit = new AuditLogService(dir);

        // 1. Legacy JSONL lines written before acbc7de (no SchemaVersion field; numeric ActionTaken 4=FirewallBlocked, 5=RolledBack, 6=Allowed)
        var legacyLogFile = Path.Combine(audit.LogsDirectory, "events-20261120.jsonl");
        File.WriteAllLines(legacyLogFile, new[]
        {
            "{\"Id\":\"leg4\",\"Severity\":4,\"Category\":7,\"ActionTaken\":4,\"Title\":\"Legacy FW\",\"ProcessId\":100}",
            "{\"Id\":\"leg5\",\"Severity\":4,\"Category\":4,\"ActionTaken\":5,\"Title\":\"Legacy Rollback\",\"ProcessId\":101}",
            "{\"Id\":\"leg6\",\"Severity\":3,\"Category\":5,\"ActionTaken\":6,\"Title\":\"Legacy Allowed\",\"ProcessId\":102}"
        }, Encoding.UTF8);

        var loadedLegacy = audit.LoadRecentEvents(10);
        var leg4 = Assert.Single(loadedLegacy, e => e.Id == "leg4");
        var leg5 = Assert.Single(loadedLegacy, e => e.Id == "leg5");
        var leg6 = Assert.Single(loadedLegacy, e => e.Id == "leg6");

        Assert.Equal(0, leg4.SchemaVersion);
        Assert.Equal(0, leg5.SchemaVersion);
        Assert.Equal(0, leg6.SchemaVersion);
        Assert.Equal(SecurityActionTaken.FirewallBlocked, leg4.ActionTaken);
        Assert.Equal(SecurityActionTaken.RolledBack, leg5.ActionTaken);
        Assert.Equal(SecurityActionTaken.Allowed, leg6.ActionTaken);

        // 2. Newly written logs MUST record SchemaVersion = 2 and round-trip both legacy & new enum values accurately!
        var actionsToRoundTrip = new[]
        {
            SecurityActionTaken.FirewallBlocked,
            SecurityActionTaken.RolledBack,
            SecurityActionTaken.Allowed,
            SecurityActionTaken.QuarantinePendingReboot,
            SecurityActionTaken.QuarantineCopyOnly,
            SecurityActionTaken.PartiallyAllowed
        };

        foreach (var action in actionsToRoundTrip)
        {
            audit.Append(new SecurityEvent
            {
                Id = $"v2_{(int)action}",
                Severity = ThreatSeverity.High,
                Category = ThreatCategory.Ransomware,
                ActionTaken = action,
                Title = $"RoundTrip {action}",
                ProcessId = 500 + (int)action
            });
        }

        var loadedAll = audit.LoadRecentEvents(20);
        foreach (var action in actionsToRoundTrip)
        {
            var found = Assert.Single(loadedAll, e => e.Id == $"v2_{(int)action}");
            Assert.Equal(SecurityEvent.CurrentSchemaVersion, found.SchemaVersion);
            Assert.Equal(action, found.ActionTaken);
        }
    }

    [Fact]
    public void RealWin32_ProcessController_SingleHandleCreationTimeGuard_And_RealSuspendResumeTerminate()
    {
        // Exercises the real Win32ProcessNativeOperations P/Invoke path (OpenProcess, GetProcessTimes,
        // QueryFullProcessImageName, NtSuspendProcess, NtResumeProcess, TerminateProcess) against live harmless child processes.
        var pingExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "ping.exe");
        Assert.True(File.Exists(pingExe));

        Process? proc1 = null;
        Process? proc2 = null;
        var procCtrl = new ProcessController();

        try
        {
            var psi = new ProcessStartInfo(pingExe, "-n 30 127.0.0.1")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            proc1 = Process.Start(psi);
            Assert.NotNull(proc1);
            Thread.Sleep(50); // Ensure distinct creation time for proc2
            proc2 = Process.Start(psi);
            Assert.NotNull(proc2);

            // 1. Real Win32 suspend + single-handle identity capture
            Assert.True(procCtrl.TrySuspendProcessDetailed(proc1!.Id, out var inst1));
            Assert.NotNull(inst1);
            Assert.True(inst1!.CreationTimeFileTimeUtc > 0);
            Assert.Equal(proc1.StartTime.ToUniversalTime().ToFileTimeUtc(), inst1.CreationTimeFileTimeUtc);
            Assert.EndsWith("ping.exe", inst1.ExecutablePath, StringComparison.OrdinalIgnoreCase);
            Assert.True(procCtrl.IsProcessSuspendedByUs(proc1.Id));

            // 2. Real Win32 PID-reuse protection: SAME PID & SAME ping.exe path, DIFFERENT creation time -> MUST NOT terminate!
            long wrongCreationTime = inst1.CreationTimeFileTimeUtc + 10_000_000L;
            Assert.False(procCtrl.TryTerminateProcessInstance(proc1.Id, wrongCreationTime, inst1.ExecutablePath));
            proc1.Refresh();
            Assert.False(proc1.HasExited, "Real process with mismatched creation time MUST NOT be terminated!");
            Assert.True(procCtrl.IsProcessSuspendedByUs(proc1.Id), "Failed mismatched terminate must keep real tracked instance intact!");

            // 3. Real Win32 NtResumeProcess -> Resumed and cleared from tracking
            var resumeRes = procCtrl.TryResumeProcessDetailed(proc1.Id, inst1.CreationTimeFileTimeUtc);
            Assert.Equal(ProcessResumeStatus.Resumed, resumeRes.Status);
            Assert.False(procCtrl.IsProcessSuspendedByUs(proc1.Id));

            // 4. Re-suspend and terminate with EXACT matching creation time on a single handle -> process terminates cleanly
            Assert.True(procCtrl.TrySuspendProcessDetailed(proc1.Id, out var inst1Again));
            Assert.Equal(inst1.CreationTimeFileTimeUtc, inst1Again!.CreationTimeFileTimeUtc);
            Assert.True(procCtrl.TryTerminateProcessInstance(proc1.Id, inst1Again.CreationTimeFileTimeUtc, inst1Again.ExecutablePath));
            Assert.True(proc1.WaitForExit(3000), "Matching real process must terminate cleanly via single-handle TerminateProcess!");
            Assert.False(procCtrl.IsProcessSuspendedByUs(proc1.Id));

            // 5. Post-exit resume classifies cleanly as AlreadyExitedOrReplaced
            Assert.Equal(ProcessResumeStatus.AlreadyExitedOrReplaced, procCtrl.TryResumeProcessDetailed(proc1.Id).Status);

            // 6. Second independent ping.exe process was never touched
            proc2!.Refresh();
            Assert.False(proc2.HasExited);
        }
        finally
        {
            procCtrl.ResumeAllSuspendedProcesses();
            foreach (var p in new[] { proc1, proc2 })
            {
                if (p is null) continue;
                try
                {
                    if (!p.HasExited) p.Kill(entireProcessTree: true);
                    p.WaitForExit(2000);
                }
                catch { }
                finally { p.Dispose(); }
            }
        }
    }

    [Fact]
    public void RealOsFileLock_RestoreOverwriteFailure_And_CrashPendingOriginalExists_PreserveFiles()
    {
        // Part A: Real Windows OS exclusive file lock during restore overwrite (ZERO test doubles!)
        var dirA = Path.Combine(_tempRoot, "real_os_lock");
        Directory.CreateDirectory(dirA);
        var targetA = Path.Combine(dirA, "locked_doc.bin");
        var quarantinedBytes = Encoding.UTF8.GetBytes("QUARANTINED-ORIGINAL-CONTENT-REAL-LOCK-TEST");
        File.WriteAllBytes(targetA, quarantinedBytes);

        var qmA = new QuarantineManager(dirA);
        var entryA = qmA.QuarantineFile(targetA, "Real OS lock test");
        Assert.False(File.Exists(targetA));

        var liveUserBytes = Encoding.UTF8.GetBytes("CURRENT-LOCKED-USER-FILE-CONTENT");
        File.WriteAllBytes(targetA, liveUserBytes);
        var expectedLiveHash = Convert.ToHexString(SHA256.HashData(liveUserBytes));

        using (var exclusiveLock = new FileStream(targetA, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            var lockedRes = qmA.RestoreFileDetailed(entryA.Id, overwriteExisting: true);
            Assert.Equal(QuarantineRestoreStatus.WriteFailed, lockedRes.Status);
            Assert.True(File.Exists(entryA.QuarantineFilePath), "Quarantine copy must survive real OS lock failure!");
            Assert.Empty(Directory.GetFiles(dirA, "*.tmp"));
        }

        // Verify the locked user file was NOT corrupted or truncated by the failed restore
        Assert.Equal(expectedLiveHash, Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(targetA))));

        // Once unlocked, retry with overwriteExisting: true succeeds cleanly
        var unlockedRes = qmA.RestoreFileDetailed(entryA.Id, overwriteExisting: true);
        Assert.Equal(QuarantineRestoreStatus.Restored, unlockedRes.Status);
        Assert.Equal(quarantinedBytes, File.ReadAllBytes(targetA));

        // Part B: Crash recovery when PendingOriginalRemoval metadata was committed BEFORE original deletion (original still exists)
        var dirB = Path.Combine(_tempRoot, "crash_original_still_exists");
        Directory.CreateDirectory(dirB);
        var targetB = Path.Combine(dirB, "still_present.bin");
        var bytesB = Encoding.UTF8.GetBytes("ORIGINAL-STILL-ON-DISK-AFTER-CRASH");
        File.WriteAllBytes(targetB, bytesB);

        var qmCrash = new QuarantineManager(
            dirB,
            deleteFileOverride: _ => throw new IOException("Simulated hard interruption before delete completed"));

        Assert.Throws<IOException>(() => qmCrash.QuarantineFile(targetB, "Crash before delete"));
        Assert.True(File.Exists(targetB));

        // Restart QuarantineManager: PendingOriginalRemoval must reconcile to CopyOnlyOriginalLocked (since original still exists!)
        var restartedQm = new QuarantineManager(dirB);
        var reconciled = Assert.Single(restartedQm.ListEntries());
        Assert.Equal(QuarantineDisposition.CopyOnlyOriginalLocked, reconciled.Disposition);

        // Restoring without overwriteExisting MUST detect conflict instead of clobbering existing original
        var conflictRes = restartedQm.RestoreFileDetailed(reconciled.Id, overwriteExisting: false);
        Assert.Equal(QuarantineRestoreStatus.DestinationConflict, conflictRes.Status);
        Assert.Equal(bytesB, File.ReadAllBytes(targetB));
    }

    [Fact]
    public void P1_5_LegacyAegisQ1StreamingPath_DetectsConflict_PreservesExistingOnWriteFailure_And_RestoresAtomically()
    {
        var dir = Path.Combine(_tempRoot, "aegisq1_streaming");
        Directory.CreateDirectory(dir);

        var target = Path.Combine(dir, "large_archive_sim.bin");
        var originalBytes = RandomNumberGenerator.GetBytes(8192);
        File.WriteAllBytes(target, originalBytes);

        // Set GCM threshold to 64 bytes so this 8 KB file deterministically exercises the real AEGISQ1 streaming quarantine & restore path.
        var qm = new QuarantineManager(dir, maxInMemoryGcmBytes: 64);
        var entry = qm.QuarantineFile(target, "AEGISQ1 streaming test");
        Assert.False(File.Exists(target));

        // Confirm on-disk file header is literally AEGISQ1\0
        var header = new byte[8];
        using (var fs = File.OpenRead(entry.QuarantineFilePath))
        {
            Assert.Equal(8, fs.Read(header, 0, 8));
        }
        Assert.Equal("AEGISQ1\0", Encoding.ASCII.GetString(header));

        // User creates a new file at destination
        var newUserBytes = Encoding.UTF8.GetBytes("NEW-USER-FILE-AT-AEGISQ1-DEST");
        File.WriteAllBytes(target, newUserBytes);
        var expectedUserHash = Convert.ToHexString(SHA256.HashData(newUserBytes));

        // 1. Conflict check (overwriteExisting=false)
        var conflict = qm.RestoreFileDetailed(entry.Id, overwriteExisting: false);
        Assert.Equal(QuarantineRestoreStatus.DestinationConflict, conflict.Status);
        Assert.Equal(expectedUserHash, Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(target))));
        Assert.True(File.Exists(entry.QuarantineFilePath));

        // 2. Write failure during AEGISQ1 temp restore leaves existing destination & quarantine copy intact
        var failingQm = new QuarantineManager(
            dir,
            writeRestoreTempOverride: (tmpPath, data) =>
            {
                File.WriteAllBytes(tmpPath, data.Take(16).ToArray());
                throw new IOException("Simulated disk full in AEGISQ1 restore");
            },
            maxInMemoryGcmBytes: 64);
        var writeFailed = failingQm.RestoreFileDetailed(entry.Id, overwriteExisting: true);
        Assert.Equal(QuarantineRestoreStatus.WriteFailed, writeFailed.Status);
        Assert.Equal(expectedUserHash, Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(target))));
        Assert.True(File.Exists(entry.QuarantineFilePath));
        Assert.Empty(Directory.GetFiles(dir, "*.tmp"));

        // 3. Clean atomic AEGISQ1 restore with overwriteExisting=true restores exact original bytes
        var restored = qm.RestoreFileDetailed(entry.Id, overwriteExisting: true);
        Assert.Equal(QuarantineRestoreStatus.Restored, restored.Status);
        Assert.Equal(originalBytes, File.ReadAllBytes(target));
        Assert.False(File.Exists(entry.QuarantineFilePath));
    }

    [Fact]
    public void RealWpfUi_ThreatPromptWindow_PartialResumeStaysOpenUntilRetrySucceeds_And_MainWindowConflictFlow()
    {
        Exception? staException = null;
        var staThread = new Thread(() =>
        {
            try
            {
                if (System.Windows.Application.Current is null)
                {
                    var wpfApp = new AegisSentinel.App.App();
                    wpfApp.InitializeComponent();
                }

                var dir = Path.Combine(_tempRoot, "wpf_ui_sta");
                Directory.CreateDirectory(dir);

                // Part A: Real WPF ThreatPromptWindow partial resume warning -> stays open -> retry closes cleanly
                var fakeNative = new FakeProcessNativeOperations();
                _ = fakeNative.RegisterProcess(92001, 133800000030010000L, Path.Combine(dir, "c1.exe"));
                var child2 = fakeNative.RegisterProcess(92002, 133800000030020000L, Path.Combine(dir, "c2.exe"));
                var procCtrl = new ProcessController(nativeOps: fakeNative);
                var freeze = procCtrl.TrySuspendProcessTreeDetailed(92000, new[] { 92001, 92002 });

                // Child 2 fails transiently on first click
                child2.NextResumeNtStatus = unchecked((int)0xC0000022);

                var store = new PolicyStore(dir);
                using var orch = new SecurityOrchestrator(store, processController: procCtrl);
                var evt = new SecurityEvent
                {
                    ProcessId = 92000,
                    ProcessName = "wpf_parent",
                    Category = ThreatCategory.Ransomware,
                    Severity = ThreatSeverity.Critical,
                    Title = "WPF 부분 재개 UI 검증",
                    Description = "실제 ThreatPromptWindow 버튼 클릭 회귀 테스트",
                    ActionTaken = SecurityActionTaken.Suspended,
                    IsProcessSuspended = false,
                    SuspendedChildProcessIds = freeze.SuspendedChildPids.ToList(),
                    SuspendedChildInstances = freeze.SuspendedChildInstances!.ToList(),
                    AttemptedChildFreezeCount = 2
                };

                var shownMessages = new List<(string Caption, string Body)>();
                var window = new ThreatPromptWindow(
                    orch,
                    evt,
                    queuedRemainingCount: 1,
                    messageBoxOverride: (msg, caption, _, _) =>
                    {
                        shownMessages.Add((caption, msg));
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

                    // First click on real WPF AllowOnceBtn -> partial failure -> warning shown & window STAYS OPEN!
                    window.AllowOnceBtn.RaiseEvent(new System.Windows.RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent));

                    Assert.False(closed, "ThreatPromptWindow must stay open when partial resume still needs retry!");
                    Assert.Single(shownMessages);
                    Assert.Contains("92002", shownMessages[0].Body);
                    Assert.Contains("부분 재개", window.StatusPillText.Text);
                    Assert.Contains("92002", window.ProcessDetailText.Text);
                    Assert.Equal(SecurityActionTaken.PartiallyAllowed, evt.ActionTaken);

                    // Clear transient failure and click AllowOnceBtn again -> resumes child 2 and CLOSES window cleanly!
                    child2.NextResumeNtStatus = null;
                    window.AllowOnceBtn.RaiseEvent(new System.Windows.RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent));

                    Assert.True(closed, "ThreatPromptWindow must close once all frozen targets are resumed!");
                    Assert.Equal(SecurityActionTaken.Allowed, evt.ActionTaken);
                    Assert.Empty(procCtrl.GetTrackedSuspendedPids());
                }
                finally
                {
                    if (!closed)
                    {
                        try { window.Close(); } catch { }
                    }
                }

                // Part B: MainWindow conflict confirmation helper -> No preserves existing file, Yes replaces atomically
                var qm = new QuarantineManager(dir);
                var docPath = Path.Combine(dir, "ui_restore_target.txt");
                var originalPayload = Encoding.UTF8.GetBytes("ORIGINAL-QUARANTINED-UI-DOC");
                File.WriteAllBytes(docPath, originalPayload);
                var qEntry = qm.QuarantineFile(docPath, "UI conflict confirmation test");

                var newerUserPayload = Encoding.UTF8.GetBytes("NEWER-USER-UI-DOC");
                File.WriteAllBytes(docPath, newerUserPayload);

                bool promptedOnNo = false;
                var declinedRes = MainWindow.ExecuteRestoreWithConflictConfirmation(qm, qEntry.Id, _ =>
                {
                    promptedOnNo = true;
                    return false;
                });
                Assert.True(promptedOnNo);
                Assert.Equal(QuarantineRestoreStatus.DestinationConflict, declinedRes.Status);
                Assert.Equal(newerUserPayload, File.ReadAllBytes(docPath));
                Assert.True(File.Exists(qEntry.QuarantineFilePath));

                bool promptedOnYes = false;
                var acceptedRes = MainWindow.ExecuteRestoreWithConflictConfirmation(qm, qEntry.Id, _ =>
                {
                    promptedOnYes = true;
                    return true;
                });
                Assert.True(promptedOnYes);
                Assert.Equal(QuarantineRestoreStatus.Restored, acceptedRes.Status);
                Assert.Equal(originalPayload, File.ReadAllBytes(docPath));
                Assert.False(File.Exists(qEntry.QuarantineFilePath));
            }
            catch (Exception ex)
            {
                staException = ex;
            }
            finally
            {
                System.Windows.Threading.Dispatcher.CurrentDispatcher.InvokeShutdown();
            }
        });

        staThread.SetApartmentState(ApartmentState.STA);
        staThread.Start();
        Assert.True(staThread.Join(TimeSpan.FromSeconds(20)), "WPF STA UI verification thread timed out!");
        if (staException is not null)
        {
            throw new Xunit.Sdk.XunitException($"WPF STA test failed: {staException}");
        }
    }
}
