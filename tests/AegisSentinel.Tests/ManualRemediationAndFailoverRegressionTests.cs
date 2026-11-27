using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using AegisSentinel.Core.Engine;
using AegisSentinel.Core.Models;
using AegisSentinel.Core.Services;

namespace AegisSentinel.Tests;

/// <summary>
/// TDD regression tests for the 4 findings reviewed on a4f5646 + local working tree:
/// - P1-1: Stale manual remediation scan results must verify PID creation time, host path, and loaded DLL
///         (0 OS TerminateProcess calls on recycled PID; identity lookup failure requires re-scan).
/// - P1-2: Mid-run ETW kernel listener drop must fail over to fallback process monitoring, surface
///         degraded/limited mode status, observe new processes, and recover cleanly back to ETW.
/// - P2-1: Malicious service remediation must report current stop state, next-boot disable state,
///         and associated file quarantine disposition separately without false completion claims.
/// - P2-2: Remediation audit log must record accurate SecurityActionTaken (e.g., RolledBack for HOSTS)
///         without incrementing Quarantined count, while preserving legacy enum numeric values 0..9.
/// </summary>
public sealed class ManualRemediationAndFailoverRegressionTests : IDisposable
{
    private readonly string _tempRoot;

    public ManualRemediationAndFailoverRegressionTests()
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

    private sealed class FakeProc
    {
        public int Pid { get; init; }
        public long CreationTimeUtc { get; init; }
        public string ExecutablePath { get; init; } = string.Empty;
        public bool IsAlive { get; set; } = true;
        public bool FailCreationTimeLookup { get; set; }
        public HashSet<string> LoadedModules { get; } = new(StringComparer.OrdinalIgnoreCase);
        public bool FailModuleLookup { get; set; }
        public int TerminateCalls { get; set; }
    }

    private sealed class ModuleAwareFakeNativeOps : IProcessNativeOperations
    {
        private readonly Dictionary<int, FakeProc> _procs = new();
        private readonly Dictionary<IntPtr, FakeProc> _handles = new();
        private long _nextHandle = 0x7000;

        public FakeProc Register(int pid, long creationTimeUtc, string path, params string[] loadedModules)
        {
            var p = new FakeProc
            {
                Pid = pid,
                CreationTimeUtc = creationTimeUtc,
                ExecutablePath = path
            };
            foreach (var m in loadedModules)
            {
                p.LoadedModules.Add(Path.GetFullPath(m));
            }
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

        public int SuspendProcess(IntPtr handle) => 0;
        public int ResumeProcess(IntPtr handle) => 0;

        public bool TerminateProcess(IntPtr handle, uint exitCode)
        {
            if (!_handles.TryGetValue(handle, out var p)) return false;
            p.TerminateCalls++;
            p.IsAlive = false;
            return true;
        }

        public bool? IsModuleLoaded(int pid, IntPtr handle, string modulePath)
        {
            if (!_handles.TryGetValue(handle, out var p) || p.FailModuleLookup)
            {
                return null;
            }
            return p.LoadedModules.Contains(Path.GetFullPath(modulePath));
        }
    }

    private sealed class ControllableEtwSessionRunner : IEtwKernelSessionRunner
    {
        private readonly object _sync = new();
        private ManualResetEventSlim? _currentGate;
        private Exception? _dropException;
        private bool _allowStart = true;

        public int StartCount { get; private set; }

        public void SetAllowStart(bool allow)
        {
            lock (_sync) { _allowStart = allow; }
        }

        public void TriggerUnexpectedDrop(string errorMessage)
        {
            lock (_sync)
            {
                _dropException = new InvalidOperationException(errorMessage);
                _currentGate?.Set();
            }
        }

        public bool TryStart(out Action runListenerBlocking, out Action stopSession)
        {
            lock (_sync)
            {
                if (!_allowStart)
                {
                    runListenerBlocking = () => { };
                    stopSession = () => { };
                    return false;
                }

                StartCount++;
                var gate = new ManualResetEventSlim(false);
                _currentGate = gate;
                _dropException = null;

                runListenerBlocking = () =>
                {
                    gate.Wait();
                    Exception? ex;
                    lock (_sync) { ex = _dropException; }
                    if (ex is not null)
                    {
                        throw ex;
                    }
                };

                stopSession = () =>
                {
                    lock (_sync)
                    {
                        _dropException = null;
                        gate.Set();
                    }
                };

                return true;
            }
        }
    }

    [Fact]
    public void P1_1_ManualRemediation_RecycledPidWithDifferentCreationTime_MustNeverTerminate_AndLookupFailureMustRequireRescan()
    {
        var nativeOps = new ModuleAwareFakeNativeOps();
        var procCtrl = new ProcessController(nativeOps: nativeOps);
        var quarantine = new QuarantineManager(_tempRoot);
        var auditLog = new AuditLogService(_tempRoot);
        var remediation = new MalwareRemediationService(procCtrl, quarantine, auditLog, _tempRoot);

        // 1A. Recycled PID with DIFFERENT creation time when original file is already gone (Process Ghosting stale finding)
        var benignRecycled = nativeOps.Register(
            pid: 4100,
            creationTimeUtc: 133800000000002000L,
            path: @"C:\Program Files\BenignEditor\editor.exe");

        var staleGhostItem = new MalwareThreatItem
        {
            Stage = MalwareScanStage.ActiveProcessAndMemory,
            ThreatName = "Trojan.Win32.ProcessGhosting",
            CategoryLabel = "Process Ghosting",
            Severity = ThreatSeverity.Critical,
            RiskScore = 95,
            TargetPath = Path.Combine(_tempRoot, "deleted_ghost.exe"),
            ProcessId = 4100,
            ProcessCreationTimeFileTimeUtc = 133800000000001000L, // Older creation time!
            HostProcessPath = Path.Combine(_tempRoot, "deleted_ghost.exe"),
            ActionType = RemediationActionType.TerminateAndQuarantine
        };

        var ghostRes = remediation.CureSingleItem(staleGhostItem);
        Assert.Equal(0, benignRecycled.TerminateCalls);
        Assert.True(benignRecycled.IsAlive);
        Assert.False(ghostRes.Success);
        Assert.Contains("재검사", ghostRes.Message, StringComparison.Ordinal);

        // 1B. Recycled PID on DLL sideloading finding with MATCHING scanned SHA-256:
        //     0 TerminateProcess calls on recycled host, while verified malicious DLL on disk is safely quarantined!
        var proxyDllPath = Path.Combine(_tempRoot, "version.dll");
        File.WriteAllText(proxyDllPath, "unsigned-proxy-dll-payload");
        var proxyDllSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(proxyDllPath)));

        var recycledHost = nativeOps.Register(
            pid: 4101,
            creationTimeUtc: 133800000000009000L,
            path: @"C:\Users\Test\BenignApp\benign.exe");

        var staleDllItem = new MalwareThreatItem
        {
            Stage = MalwareScanStage.ActiveProcessAndMemory,
            ThreatName = "SupplyChain.LiveDllSideloading.ActiveHijack",
            CategoryLabel = "실시간 DLL 사이드로딩 공격",
            Severity = ThreatSeverity.Critical,
            RiskScore = 98,
            TargetPath = proxyDllPath,
            ProcessId = 4101,
            ProcessCreationTimeFileTimeUtc = 133800000000001000L, // Older creation time!
            HostProcessPath = @"C:\Games\Launcher\launcher.exe",
            Sha256 = proxyDllSha256,
            ActionType = RemediationActionType.TerminateAndQuarantine
        };

        var dllStaleRes = remediation.CureSingleItem(staleDllItem);
        Assert.Equal(0, recycledHost.TerminateCalls);
        Assert.True(recycledHost.IsAlive);
        Assert.False(File.Exists(proxyDllPath)); // Verified identical malicious DLL on disk is safely quarantined!
        Assert.True(dllStaleRes.Success);

        // 1C. Same PID + same creation time + same host path, BUT target DLL is NOT loaded -> 0 TerminateProcess calls!
        var hostWithoutDll = nativeOps.Register(
            pid: 4102,
            creationTimeUtc: 133800000000003000L,
            path: @"C:\Games\Launcher\launcher.exe"); // version2.dll is NOT in LoadedModules!

        var missingDllPath = Path.Combine(_tempRoot, "version2.dll");
        var unloadedDllItem = new MalwareThreatItem
        {
            Stage = MalwareScanStage.ActiveProcessAndMemory,
            ThreatName = "SupplyChain.LiveDllSideloading.ActiveHijack",
            CategoryLabel = "실시간 DLL 사이드로딩 공격",
            Severity = ThreatSeverity.Critical,
            RiskScore = 98,
            TargetPath = missingDllPath,
            ProcessId = 4102,
            ProcessCreationTimeFileTimeUtc = 133800000000003000L,
            HostProcessPath = @"C:\Games\Launcher\launcher.exe",
            ActionType = RemediationActionType.TerminateAndQuarantine
        };

        var unloadedDllRes = remediation.CureSingleItem(unloadedDllItem);
        Assert.Equal(0, hostWithoutDll.TerminateCalls);
        Assert.True(hostWithoutDll.IsAlive);
        Assert.False(unloadedDllRes.Success);
        Assert.Contains("재검사", unloadedDllRes.Message, StringComparison.Ordinal);

        // 1D. Identity lookup failure (GetProcessTimes fails) -> 0 TerminateProcess calls & must require re-scan!
        var lookupFailProc = nativeOps.Register(
            pid: 4103,
            creationTimeUtc: 133800000000004000L,
            path: Path.Combine(_tempRoot, "lookup_fail.exe"));
        lookupFailProc.FailCreationTimeLookup = true;

        var lookupFailItem = new MalwareThreatItem
        {
            Stage = MalwareScanStage.ActiveProcessAndMemory,
            ThreatName = "Trojan.Win32.ProcessGhosting",
            Severity = ThreatSeverity.Critical,
            RiskScore = 95,
            TargetPath = lookupFailProc.ExecutablePath,
            ProcessId = 4103,
            ProcessCreationTimeFileTimeUtc = 133800000000004000L,
            HostProcessPath = lookupFailProc.ExecutablePath,
            ActionType = RemediationActionType.TerminateAndQuarantine
        };

        var lookupFailRes = remediation.CureSingleItem(lookupFailItem);
        Assert.Equal(0, lookupFailProc.TerminateCalls);
        Assert.True(lookupFailProc.IsAlive);
        Assert.False(lookupFailRes.Success);
        Assert.Contains("재검사", lookupFailRes.Message, StringComparison.Ordinal);

        // 1E. Matching PID + matching creation time + matching host + loaded DLL + matching SHA-256 -> terminates & quarantines cleanly!
        var activeHijackDll = Path.Combine(_tempRoot, "winmm.dll");
        File.WriteAllText(activeHijackDll, "active-sideload-dll");
        var activeHijackDllSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(activeHijackDll)));
        var verifiedHost = nativeOps.Register(
            pid: 4104,
            creationTimeUtc: 133800000000005000L,
            path: @"C:\Games\Launcher\launcher.exe",
            loadedModules: [activeHijackDll]);

        var validDllItem = new MalwareThreatItem
        {
            Stage = MalwareScanStage.ActiveProcessAndMemory,
            ThreatName = "SupplyChain.LiveDllSideloading.ActiveHijack",
            Severity = ThreatSeverity.Critical,
            RiskScore = 98,
            TargetPath = activeHijackDll,
            ProcessId = 4104,
            ProcessCreationTimeFileTimeUtc = 133800000000005000L,
            HostProcessPath = @"C:\Games\Launcher\launcher.exe",
            Sha256 = activeHijackDllSha256,
            TargetFileExistedAtScan = true,
            ActionType = RemediationActionType.TerminateAndQuarantine
        };

        var validRes = remediation.CureSingleItem(validDllItem);
        Assert.Equal(1, verifiedHost.TerminateCalls);
        Assert.False(verifiedHost.IsAlive);
        Assert.True(validRes.Success);
        Assert.False(File.Exists(activeHijackDll));
    }

    [Fact]
    public void P1_1B_ManualRemediation_ZeroCreationTimeWithSameHostPath_MustHoldTerminationAndRequireRescan()
    {
        var nativeOps = new ModuleAwareFakeNativeOps();
        var procCtrl = new ProcessController(nativeOps: nativeOps);
        var quarantine = new QuarantineManager(_tempRoot);
        var auditLog = new AuditLogService(_tempRoot);
        var remediation = new MalwareRemediationService(procCtrl, quarantine, auditLog, _tempRoot);

        // Same path running as a newer process instance, while scan item has ProcessCreationTimeFileTimeUtc == 0
        var exePath = Path.Combine(_tempRoot, "restarted_same_path.exe");
        File.WriteAllText(exePath, "updated-clean-binary-at-same-path");
        var exeSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(exePath)));

        var newerProcAtSamePath = nativeOps.Register(
            pid: 4200,
            creationTimeUtc: 133800000000099999L,
            path: exePath);

        var itemWithoutCreationTime = new MalwareThreatItem
        {
            Stage = MalwareScanStage.ActiveProcessAndMemory,
            ThreatName = "Heuristic.Win32.SuspiciousFile",
            Severity = ThreatSeverity.High,
            RiskScore = 82,
            TargetPath = exePath,
            ProcessId = 4200,
            ProcessCreationTimeFileTimeUtc = 0, // Missing creation time!
            HostProcessPath = exePath,          // Same path exists!
            Sha256 = exeSha256,
            ActionType = RemediationActionType.TerminateAndQuarantine
        };

        var res = remediation.CureSingleItem(itemWithoutCreationTime);
        Assert.Equal(0, newerProcAtSamePath.TerminateCalls);
        Assert.True(newerProcAtSamePath.IsAlive);
        Assert.False(res.Success);
        Assert.Contains("재검사", res.Message, StringComparison.Ordinal);
        Assert.True(File.Exists(exePath));
        Assert.Empty(quarantine.ListEntries());

        // Same check for DLL sideloading item with ProcessCreationTimeFileTimeUtc == 0 even when HostProcessPath + DLL match
        var dllPath = Path.Combine(_tempRoot, "dbghelp.dll");
        File.WriteAllText(dllPath, "dll-content");
        var hostProc = nativeOps.Register(
            pid: 4201,
            creationTimeUtc: 133800000000088888L,
            path: @"C:\Games\Launcher\launcher.exe",
            loadedModules: [dllPath]);

        var dllWithoutCreationTime = new MalwareThreatItem
        {
            Stage = MalwareScanStage.ActiveProcessAndMemory,
            ThreatName = "SupplyChain.LiveDllSideloading.ActiveHijack",
            Severity = ThreatSeverity.Critical,
            RiskScore = 98,
            TargetPath = dllPath,
            ProcessId = 4201,
            ProcessCreationTimeFileTimeUtc = 0,
            HostProcessPath = @"C:\Games\Launcher\launcher.exe",
            Sha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(dllPath))),
            ActionType = RemediationActionType.TerminateAndQuarantine
        };

        var dllRes = remediation.CureSingleItem(dllWithoutCreationTime);
        Assert.Equal(0, hostProc.TerminateCalls);
        Assert.True(hostProc.IsAlive);
        Assert.False(dllRes.Success);
        Assert.Contains("재검사", dllRes.Message, StringComparison.Ordinal);
        Assert.True(File.Exists(dllPath));
        Assert.Empty(quarantine.ListEntries());
    }

    [Fact]
    public void P1_1C_ManualRemediation_AfterAlreadyExitedOrReplaced_MustVerifyScannedFileSha256BeforeQuarantine()
    {
        var nativeOps = new ModuleAwareFakeNativeOps();
        var procCtrl = new ProcessController(nativeOps: nativeOps);
        var quarantine = new QuarantineManager(_tempRoot);
        var auditLog = new AuditLogService(_tempRoot);
        var remediation = new MalwareRemediationService(procCtrl, quarantine, auditLog, _tempRoot);

        // Case 1: PID replaced (AlreadyExitedOrReplaced) AND file at TargetPath was replaced with different content -> MUST NOT quarantine!
        var replacedFilePath = Path.Combine(_tempRoot, "replaced_app.exe");
        var scannedOriginalSha256 = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("old-malicious-v1")));
        File.WriteAllText(replacedFilePath, "new-legitimate-updated-v2");

        var recycledProc = nativeOps.Register(
            pid: 4300,
            creationTimeUtc: 133800000000050000L,
            path: @"C:\Program Files\SafeApp\safe.exe");

        var replacedFileItem = new MalwareThreatItem
        {
            Stage = MalwareScanStage.ActiveProcessAndMemory,
            ThreatName = "Trojan.Win32.StaleReplaced",
            Severity = ThreatSeverity.Critical,
            RiskScore = 90,
            TargetPath = replacedFilePath,
            ProcessId = 4300,
            ProcessCreationTimeFileTimeUtc = 133800000000010000L, // Different from live PID 4300 -> AlreadyExitedOrReplaced
            HostProcessPath = replacedFilePath,
            Sha256 = scannedOriginalSha256, // Does NOT match current file on disk!
            ActionType = RemediationActionType.TerminateAndQuarantine
        };

        var replacedRes = remediation.CureSingleItem(replacedFileItem);
        Assert.Equal(0, recycledProc.TerminateCalls);
        Assert.False(replacedRes.Success);
        Assert.Contains("재검사", replacedRes.Message, StringComparison.Ordinal);
        Assert.True(File.Exists(replacedFilePath));
        Assert.Equal("new-legitimate-updated-v2", File.ReadAllText(replacedFilePath));
        Assert.Empty(quarantine.ListEntries());

        // Case 2: PID replaced (AlreadyExitedOrReplaced) AND scan item has NO Sha256 -> cannot verify same file -> MUST hold quarantine!
        var unhashedFilePath = Path.Combine(_tempRoot, "unhashed_app.exe");
        File.WriteAllText(unhashedFilePath, "potentially-replaced-file");

        var missingHashItem = new MalwareThreatItem
        {
            Stage = MalwareScanStage.ActiveProcessAndMemory,
            ThreatName = "Trojan.Win32.MissingHash",
            Severity = ThreatSeverity.High,
            RiskScore = 85,
            TargetPath = unhashedFilePath,
            ProcessId = 4300,
            ProcessCreationTimeFileTimeUtc = 133800000000010000L,
            HostProcessPath = unhashedFilePath,
            Sha256 = string.Empty,
            ActionType = RemediationActionType.TerminateAndQuarantine
        };

        var missingHashRes = remediation.CureSingleItem(missingHashItem);
        Assert.Equal(0, recycledProc.TerminateCalls);
        Assert.False(missingHashRes.Success);
        Assert.Contains("재검사", missingHashRes.Message, StringComparison.Ordinal);
        Assert.True(File.Exists(unhashedFilePath));
        Assert.Empty(quarantine.ListEntries());

        // Case 3: PID replaced (AlreadyExitedOrReplaced) AND disk file matches scanned Sha256 -> quarantine succeeds cleanly!
        var matchingFilePath = Path.Combine(_tempRoot, "verified_same_malware.exe");
        File.WriteAllText(matchingFilePath, "confirmed-same-malware-bytes");
        var matchingSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(matchingFilePath)));

        var matchingHashItem = new MalwareThreatItem
        {
            Stage = MalwareScanStage.ActiveProcessAndMemory,
            ThreatName = "Trojan.Win32.ConfirmedHash",
            Severity = ThreatSeverity.Critical,
            RiskScore = 95,
            TargetPath = matchingFilePath,
            ProcessId = 4300,
            ProcessCreationTimeFileTimeUtc = 133800000000010000L,
            HostProcessPath = matchingFilePath,
            Sha256 = matchingSha256,
            ActionType = RemediationActionType.TerminateAndQuarantine
        };

        var matchingRes = remediation.CureSingleItem(matchingHashItem);
        Assert.Equal(0, recycledProc.TerminateCalls);
        Assert.True(matchingRes.Success);
        Assert.Equal(SecurityActionTaken.Quarantined, matchingRes.ActionTaken);
        Assert.False(File.Exists(matchingFilePath));
        Assert.Single(quarantine.ListEntries());
    }

    [Fact]
    public async Task P1_2_EtwKernelDrop_MustEnterDegradedFallbackObserveNewProcess_AndRecoverEtwCleanly()
    {
        var policyStore = new PolicyStore(_tempRoot);
        var policy = GuardPolicy.CreateDefault();
        policy.EnableEtwTelemetry = true;
        policy.DeployCanaryFiles = false;
        policy.EnableAutoRecoveryVault = false;
        policy.EnableMemoryInjectionGuard = false;
        policy.ProtectedFolders.Clear();
        policyStore.Save(policy);

        var nativeOps = new ModuleAwareFakeNativeOps();
        var procCtrl = new ProcessController(nativeOps: nativeOps);
        var etwRunner = new ControllableEtwSessionRunner();

        var snapshotLock = new object();
        var currentProcesses = new List<(int Pid, string Name)>
        {
            (2000, "existing_benign")
        };

        using var orchestrator = new SecurityOrchestrator(
            policyStore: policyStore,
            processController: procCtrl,
            etwSessionRunner: etwRunner,
            isElevatedProvider: () => true,
            fallbackProcessSnapshotProvider: () =>
            {
                lock (snapshotLock) { return currentProcesses.ToList(); }
            },
            etwRecoveryInterval: TimeSpan.FromMinutes(10));

        var stateHistory = new ConcurrentQueue<(TelemetryHealthState State, string Message)>();
        var degradedTcs = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var recoveredTcs = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var observedNewPidTcs = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);

        orchestrator.TelemetryStateChanged += (state, msg) =>
        {
            stateHistory.Enqueue((state, msg));
            if (state == TelemetryHealthState.DegradedFallbackActive)
            {
                degradedTcs.TrySetResult(msg);
            }
            else if (state == TelemetryHealthState.EtwKernelActive && degradedTcs.Task.IsCompleted)
            {
                recoveredTcs.TrySetResult(msg);
            }
        };

        orchestrator.FallbackProcessObserved += (pid, _, _) =>
        {
            if (pid == 7788)
            {
                observedNewPidTcs.TrySetResult(pid);
            }
        };

        // 1. Normal ETW kernel start
        orchestrator.Start();
        Assert.True(orchestrator.IsRunning);
        Assert.True(orchestrator.IsEtwKernelModeActive);
        Assert.Equal(TelemetryHealthState.EtwKernelActive, orchestrator.TelemetryState);
        Assert.False(orchestrator.IsDegradedFallbackActive);
        Assert.False(orchestrator.IsFallbackProcessPollingActive);

        // 2. Mid-run ETW kernel listener drop -> must transition to degraded/limited fallback mode
        etwRunner.TriggerUnexpectedDrop("Simulated kernel ETW buffer overflow / session loss");
        var completedDegraded = await Task.WhenAny(degradedTcs.Task, Task.Delay(5000));
        Assert.Same(degradedTcs.Task, completedDegraded);
        var degradedMsg = await degradedTcs.Task;

        Assert.Equal(TelemetryHealthState.DegradedFallbackActive, orchestrator.TelemetryState);
        Assert.True(orchestrator.IsDegradedFallbackActive);
        Assert.False(orchestrator.IsEtwKernelModeActive);
        Assert.True(orchestrator.IsFallbackProcessPollingActive);
        Assert.Contains("제한 모드", degradedMsg, StringComparison.Ordinal);

        // 3. Fallback monitor must now observe a newly spawned process!
        var fakeNewExe = Path.Combine(_tempRoot, "newly_spawned_after_drop.exe");
        File.WriteAllText(fakeNewExe, "dummy");
        nativeOps.Register(7788, 133800000000007788L, fakeNewExe);
        lock (snapshotLock)
        {
            currentProcesses.Add((7788, "newly_spawned_after_drop"));
        }

        var completedObserved = await Task.WhenAny(observedNewPidTcs.Task, Task.Delay(5000));
        Assert.Same(observedNewPidTcs.Task, completedObserved);
        Assert.Equal(7788, await observedNewPidTcs.Task);

        // 4. ETW recovery succeeds -> must cleanly return to EtwKernelActive & stop redundant fallback process polling
        bool recovered = orchestrator.TryRecoverEtwKernelTelemetry();
        Assert.True(recovered);

        var completedRecovered = await Task.WhenAny(recoveredTcs.Task, Task.Delay(5000));
        Assert.Same(recoveredTcs.Task, completedRecovered);

        Assert.Equal(TelemetryHealthState.EtwKernelActive, orchestrator.TelemetryState);
        Assert.True(orchestrator.IsEtwKernelModeActive);
        Assert.False(orchestrator.IsDegradedFallbackActive);
        Assert.False(orchestrator.IsFallbackProcessPollingActive);
        Assert.Equal(2, etwRunner.StartCount);

        orchestrator.Stop();
        Assert.Equal(TelemetryHealthState.Stopped, orchestrator.TelemetryState);
    }

    [Fact]
    public void P2_1_ServiceRemediation_StopFailed_ConfigDisabled_FileCopyOnly_MustReportAllThreeSeparately()
    {
        var svcBinary = Path.Combine(_tempRoot, "evil_service.exe");
        File.WriteAllText(svcBinary, "malicious-service-binary-payload");
        var svcBinarySha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(svcBinary)));

        var procCtrl = new ProcessController();
        // Force quarantine delete failure so associated file ends up as CopyOnlyOriginalLocked
        var quarantine = new QuarantineManager(
            baseDirectory: _tempRoot,
            deleteFileOverride: _ => false);
        var auditLog = new AuditLogService(_tempRoot);

        var commandsExecuted = new List<string>();
        var remediation = new MalwareRemediationService(
            procCtrl,
            quarantine,
            auditLog,
            _tempRoot,
            commandRunnerOverride: (exe, args) =>
            {
                var cmd = $"{exe} {string.Join(' ', args)}";
                commandsExecuted.Add(cmd);
                var argList = args.ToList();
                if (argList.Count >= 2 && argList[0].Equals("stop", StringComparison.OrdinalIgnoreCase))
                {
                    return (false, "액세스가 거부되었습니다 (ERROR_ACCESS_DENIED)");
                }
                if (argList.Count >= 3 && argList[0].Equals("config", StringComparison.OrdinalIgnoreCase))
                {
                    return (true, string.Empty);
                }
                return (false, "unexpected command");
            });

        var svcThreat = new MalwareThreatItem
        {
            Stage = MalwareScanStage.PersistenceAndService,
            ThreatName = "Persistence.Service.Suspicious",
            CategoryLabel = "악성 의심 Windows 서비스",
            Severity = ThreatSeverity.Critical,
            RiskScore = 90,
            TargetPath = @"HKLM\SYSTEM\CurrentControlSet\Services\EvilBackdoorSvc",
            EntryName = "EvilBackdoorSvc",
            AssociatedFilePath = svcBinary,
            AssociatedFileSha256 = svcBinarySha256,
            ActionType = RemediationActionType.DisableMaliciousService
        };

        var result = remediation.CureSingleItem(svcThreat);

        // Must NOT falsely report full success when stop failed and original file was NOT removed!
        Assert.False(result.Success);
        Assert.Equal(false, result.ServiceStopped);
        Assert.Equal(true, result.ServiceDisabledForNextBoot);
        Assert.Equal(QuarantineDisposition.CopyOnlyOriginalLocked, result.FileQuarantineDisposition);

        // Must report all 3 dimensions distinctly and NEVER claim full stop or full quarantine!
        Assert.Contains("중지 실패", result.Message, StringComparison.Ordinal);
        Assert.Contains("비활성화 완료", result.Message, StringComparison.Ordinal);
        Assert.Contains("사본만 보관", result.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("중지 및 비활성화 완료", result.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("연계 파일 격리 완료", result.Message, StringComparison.Ordinal);

        // Audit log must NOT record SecurityActionTaken.Quarantined when original was not removed!
        var audited = auditLog.LoadRecentEvents(10);
        var svcAudit = Assert.Single(audited);
        Assert.Equal(SecurityActionTaken.QuarantineCopyOnly, svcAudit.ActionTaken);
    }

    [Fact]
    public async Task P2_2_HostsOnlyRemediation_MustAuditAsRolledBack_AndNotIncrementQuarantinedCount()
    {
        // Guard against any accidental renumbering of persisted SecurityActionTaken enum values 0..9
        Assert.Equal(0, (int)SecurityActionTaken.Logged);
        Assert.Equal(1, (int)SecurityActionTaken.Suspended);
        Assert.Equal(2, (int)SecurityActionTaken.Terminated);
        Assert.Equal(3, (int)SecurityActionTaken.Quarantined);
        Assert.Equal(4, (int)SecurityActionTaken.FirewallBlocked);
        Assert.Equal(5, (int)SecurityActionTaken.RolledBack);
        Assert.Equal(6, (int)SecurityActionTaken.Allowed);
        Assert.Equal(7, (int)SecurityActionTaken.QuarantinePendingReboot);
        Assert.Equal(8, (int)SecurityActionTaken.QuarantineCopyOnly);
        Assert.Equal(9, (int)SecurityActionTaken.PartiallyAllowed);

        var tempHosts = Path.Combine(_tempRoot, "hosts");
        File.WriteAllText(
            tempHosts,
            "# Test HOSTS\r\n127.0.0.1 localhost\r\n198.51.100.77 accounts.google.com\r\n",
            new UTF8Encoding(false));

        var procCtrl = new ProcessController();
        var quarantine = new QuarantineManager(_tempRoot);
        var auditLog = new AuditLogService(_tempRoot);
        bool baselineRefreshed = false;

        var remediation = new MalwareRemediationService(
            procCtrl,
            quarantine,
            auditLog,
            _tempRoot,
            onHostsRepaired: () => baselineRefreshed = true,
            commandRunnerOverride: (_, _) => (true, string.Empty));

        var hostsThreat = new MalwareThreatItem
        {
            Stage = MalwareScanStage.SystemAndNetworkRepair,
            ThreatName = "Hijacker.Network.HostsRedirection",
            CategoryLabel = "HOSTS 변조",
            Severity = ThreatSeverity.High,
            RiskScore = 85,
            TargetPath = tempHosts,
            EntryName = "198.51.100.77 accounts.google.com",
            ActionType = RemediationActionType.CleanHostsFile
        };

        var summary = await remediation.CureSelectedAsync([hostsThreat]);
        var res = Assert.Single(summary.Results);

        Assert.True(res.Success);
        Assert.Equal(SecurityActionTaken.RolledBack, res.ActionTaken);
        Assert.True(baselineRefreshed);

        var repairedContent = File.ReadAllText(tempHosts);
        Assert.Contains("127.0.0.1 localhost", repairedContent, StringComparison.Ordinal);
        Assert.Contains("# [AegisSentinel MZK Removed] 198.51.100.77 accounts.google.com", repairedContent, StringComparison.Ordinal);

        var events = auditLog.LoadRecentEvents(20);
        var hostsAudit = Assert.Single(events);
        Assert.Equal(SecurityActionTaken.RolledBack, hostsAudit.ActionTaken);
        Assert.Equal(0, events.Count(e => e.ActionTaken == SecurityActionTaken.Quarantined));
    }

    [Fact]
    public void P1_R1_ExeQuarantineAfterProcessReplaced_MustNotEnumerateAndTerminateNewSamePathInstance()
    {
        var exePath = Path.Combine(_tempRoot, "restarted_target.exe");
        File.WriteAllText(exePath, "identical-exe-content");
        var exeSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(exePath)));

        var nativeOps = new ModuleAwareFakeNativeOps();
        var procCtrl = new ProcessController(nativeOps: nativeOps);
        var quarantine = new QuarantineManager(_tempRoot);
        var auditLog = new AuditLogService(_tempRoot);
        var remediation = new MalwareRemediationService(procCtrl, quarantine, auditLog, _tempRoot);

        // Spawn a harmless live OS process solely so its real PID appears in Process.GetProcesses(),
        // then map that PID in our mock nativeOps as a NEWER process instance running from the same exePath.
        var pingExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "PING.EXE");
        using var liveHolder = Process.Start(new ProcessStartInfo(pingExe, "-n 20 127.0.0.1")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        })!;

        try
        {
            var newSamePathInstance = nativeOps.Register(
                pid: liveHolder.Id,
                creationTimeUtc: 133800000000090000L, // Newer instance!
                path: exePath);

            // Original scanned PID 4599 already exited/replaced, while a newer instance of the same EXE is running.
            var staleExeItem = new MalwareThreatItem
            {
                Stage = MalwareScanStage.ActiveProcessAndMemory,
                ThreatName = "Heuristic.Win32.SuspiciousExe",
                Severity = ThreatSeverity.High,
                RiskScore = 88,
                TargetPath = exePath,
                ProcessId = 4599,
                ProcessCreationTimeFileTimeUtc = 133800000000010000L,
                HostProcessPath = exePath,
                Sha256 = exeSha256,
                TargetFileExistedAtScan = true,
                ActionType = RemediationActionType.TerminateAndQuarantine
            };

            var res = remediation.CureSingleItem(staleExeItem);

            // Must NEVER terminate the newly spawned same-path instance via path enumeration!
            Assert.Equal(0, newSamePathInstance.TerminateCalls);
            Assert.True(newSamePathInstance.IsAlive);
            Assert.True(res.Success);
            Assert.False(File.Exists(exePath));
        }
        finally
        {
            try { if (!liveHolder.HasExited) liveHolder.Kill(); liveHolder.WaitForExit(2000); } catch { }
        }
    }

    [Fact]
    public void P1_R2_ProcessGhostingTerminated_NewFileAppearedAtSamePathBeforeCure_MustPreserveNewFile()
    {
        var ghostPath = Path.Combine(_tempRoot, "ghost_then_new_file.exe");
        var nativeOps = new ModuleAwareFakeNativeOps();
        var procCtrl = new ProcessController(nativeOps: nativeOps);
        var quarantine = new QuarantineManager(_tempRoot);
        var auditLog = new AuditLogService(_tempRoot);
        var remediation = new MalwareRemediationService(procCtrl, quarantine, auditLog, _tempRoot);

        // Process Ghosting detected when NO file existed on disk at scan time
        var ghostProc = nativeOps.Register(
            pid: 4600,
            creationTimeUtc: 133800000000012345L,
            path: ghostPath);

        var ghostItem = new MalwareThreatItem
        {
            Stage = MalwareScanStage.ActiveProcessAndMemory,
            ThreatName = "Trojan.Win32.ProcessGhosting",
            CategoryLabel = "Process Ghosting (디스크 삭제 실행)",
            Severity = ThreatSeverity.Critical,
            RiskScore = 95,
            TargetPath = ghostPath,
            ProcessId = 4600,
            ProcessCreationTimeFileTimeUtc = 133800000000012345L,
            HostProcessPath = ghostPath,
            Sha256 = string.Empty,
            TargetFileExistedAtScan = false,
            ActionType = RemediationActionType.TerminateAndQuarantine
        };

        // Before the user clicks Cure, a brand-new legitimate file is created at ghostPath!
        File.WriteAllText(ghostPath, "brand-new-legitimate-file-created-after-scan");

        var res = remediation.CureSingleItem(ghostItem);

        // Original ghost process must be terminated, AND the newly created file must NOT be quarantined!
        Assert.Equal(1, ghostProc.TerminateCalls);
        Assert.False(ghostProc.IsAlive);
        Assert.True(res.Success);
        Assert.Equal(SecurityActionTaken.Terminated, res.ActionTaken);
        Assert.True(File.Exists(ghostPath));
        Assert.Equal("brand-new-legitimate-file-created-after-scan", File.ReadAllText(ghostPath));
        Assert.Empty(quarantine.ListEntries());
    }

    [Fact]
    public void P1_R3_ServiceAndTaskAssociatedFileChangedOrUnhashed_MustPreserveFileAndReportBothActionsSeparately()
    {
        var nativeOps = new ModuleAwareFakeNativeOps();
        var procCtrl = new ProcessController(nativeOps: nativeOps);
        var quarantine = new QuarantineManager(_tempRoot);
        var auditLog = new AuditLogService(_tempRoot);
        var remediation = new MalwareRemediationService(
            procCtrl,
            quarantine,
            auditLog,
            _tempRoot,
            commandRunnerOverride: (_, _) => (true, string.Empty));

        // 1. Service associated file was updated between scan and remediation -> stop+disable reported, file preserved & held!
        var svcBin = Path.Combine(_tempRoot, "updated_service_bin.exe");
        var oldSvcSha = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("old-malicious-svc-v1")));
        File.WriteAllText(svcBin, "legitimate-updated-svc-v2");

        var svcItem = new MalwareThreatItem
        {
            Stage = MalwareScanStage.PersistenceAndService,
            ThreatName = "Trojan.Service.SuspiciousDropPath",
            Severity = ThreatSeverity.Critical,
            RiskScore = 90,
            TargetPath = @"HKLM\SYSTEM\CurrentControlSet\Services\UpdatedSvc",
            EntryName = "UpdatedSvc",
            AssociatedFilePath = svcBin,
            AssociatedFileSha256 = oldSvcSha,
            ActionType = RemediationActionType.DisableMaliciousService
        };

        var svcRes = remediation.CureSingleItem(svcItem);
        Assert.False(svcRes.Success);
        Assert.Equal(true, svcRes.ServiceStopped);
        Assert.Equal(true, svcRes.ServiceDisabledForNextBoot);
        Assert.Equal(QuarantineDisposition.OriginalChangedNotRemoved, svcRes.FileQuarantineDisposition);
        Assert.Equal(SecurityActionTaken.RolledBack, svcRes.ActionTaken);
        Assert.Contains("중지 완료", svcRes.Message, StringComparison.Ordinal);
        Assert.Contains("비활성화 완료", svcRes.Message, StringComparison.Ordinal);
        Assert.Contains("보존", svcRes.Message, StringComparison.Ordinal);
        Assert.Contains("재검사", svcRes.Message, StringComparison.Ordinal);
        Assert.True(File.Exists(svcBin));
        Assert.Equal("legitimate-updated-svc-v2", File.ReadAllText(svcBin));
        Assert.Empty(quarantine.ListEntries());

        // 2. Scheduled task definition matches scan, while associated file was updated -> task delete reported, file preserved & held!
        var taskBin = Path.Combine(_tempRoot, "updated_task_bin.exe");
        var oldTaskSha = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("old-task-v1")));
        File.WriteAllText(taskBin, "legitimate-updated-task-v2");

        var taskXml = $"""
            <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
              <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
              <Actions Context="Author"><Exec><Command>{taskBin}</Command><Arguments>--run-hidden</Arguments></Exec></Actions>
            </Task>
            """;
        var taskDefHash = PersistenceMonitor.ComputeScheduledTaskDefinitionSha256(@"\SuspiciousUpdaterTask", taskXml);

        var remediationWithTaskReader = new MalwareRemediationService(
            procCtrl,
            quarantine,
            auditLog,
            _tempRoot,
            commandRunnerOverride: (_, _) => (true, string.Empty),
            scheduledTaskDefinitionReaderOverride: _ => (true, taskXml, string.Empty));

        var taskItem = new MalwareThreatItem
        {
            Stage = MalwareScanStage.PersistenceAndService,
            ThreatName = "Trojan.Persistence.MaliciousCommand",
            Severity = ThreatSeverity.Critical,
            RiskScore = 90,
            TargetPath = "TaskScheduler",
            EntryName = @"\SuspiciousUpdaterTask",
            AssociatedFilePath = taskBin,
            AssociatedFileSha256 = oldTaskSha,
            ScheduledTaskDefinitionSha256 = taskDefHash,
            ActionType = RemediationActionType.DeleteScheduledTask
        };

        var taskRes = remediationWithTaskReader.CureSingleItem(taskItem);
        Assert.False(taskRes.Success);
        Assert.Equal(true, taskRes.ScheduledTaskDeleted);
        Assert.Equal(QuarantineDisposition.OriginalChangedNotRemoved, taskRes.FileQuarantineDisposition);
        Assert.Equal(SecurityActionTaken.RolledBack, taskRes.ActionTaken);
        Assert.Contains("예약 작업 제거 완료", taskRes.Message, StringComparison.Ordinal);
        Assert.Contains("보존", taskRes.Message, StringComparison.Ordinal);
        Assert.Contains("재검사", taskRes.Message, StringComparison.Ordinal);
        Assert.True(File.Exists(taskBin));
        Assert.Equal("legitimate-updated-task-v2", File.ReadAllText(taskBin));
        Assert.Empty(quarantine.ListEntries());

        // 3. Associated file with missing AssociatedFileSha256 -> quarantine held, file preserved!
        var unhashedSvcBin = Path.Combine(_tempRoot, "unhashed_svc.exe");
        File.WriteAllText(unhashedSvcBin, "unhashed-binary");
        var unhashedSvcItem = new MalwareThreatItem
        {
            Stage = MalwareScanStage.PersistenceAndService,
            ThreatName = "Trojan.Service.SuspiciousDropPath",
            Severity = ThreatSeverity.High,
            RiskScore = 85,
            TargetPath = @"HKLM\SYSTEM\CurrentControlSet\Services\UnhashedSvc",
            EntryName = "UnhashedSvc",
            AssociatedFilePath = unhashedSvcBin,
            AssociatedFileSha256 = null,
            ActionType = RemediationActionType.DisableMaliciousService
        };

        var unhashedRes = remediation.CureSingleItem(unhashedSvcItem);
        Assert.False(unhashedRes.Success);
        Assert.Contains("재검사", unhashedRes.Message, StringComparison.Ordinal);
        Assert.True(File.Exists(unhashedSvcBin));
        Assert.Empty(quarantine.ListEntries());
    }

    [Fact]
    public void P2_R4_FallbackMonitor_RecycledPidWithDifferentCreationTimeAcrossConsecutivePolls_MustEmitNewProcessOnce()
    {
        var nativeOps = new ModuleAwareFakeNativeOps();
        var procCtrl = new ProcessController(nativeOps: nativeOps);
        var sigVerifier = new SignatureVerifier();
        var treeTracker = new ProcessTreeTracker();
        var intelStore = new ThreatIntelStore(_tempRoot);
        var customRules = new CustomRuleEngine(_tempRoot);
        var evaluator = new ProcessRuleEvaluator(treeTracker, intelStore, customRules);
        var ransomwareDetector = new RansomwareDetector();
        var canaryManager = new CanaryManager();
        var policy = GuardPolicy.CreateDefault();
        policy.ProtectedFolders.Clear();

        var pathA = Path.Combine(_tempRoot, "proc_a.exe");
        var pathB = Path.Combine(_tempRoot, "proc_b.exe");
        File.WriteAllText(pathA, "a");
        File.WriteAllText(pathB, "b");

        nativeOps.Register(5500, 133800000000010000L, pathA);
        var snapshot = new List<(int Pid, string Name)> { (5500, "proc_a") };

        using var monitor = new FallbackProcessAndFileMonitor(
            procCtrl,
            sigVerifier,
            evaluator,
            ransomwareDetector,
            canaryManager,
            () => policy,
            processSnapshotProvider: () => snapshot.ToList(),
            pollInterval: TimeSpan.FromMinutes(10));

        var observed = new List<(int Pid, string Name, string Path)>();
        monitor.NewProcessObserved += (pid, name, path) => observed.Add((pid, name, path));

        // Seed snapshot 1: PID 5500 (proc_a, creationTime 10000)
        monitor.Start(processMonitoringHandledByEtw: false);
        Assert.Empty(observed);

        // Between consecutive polls, proc_a exits and proc_b reuses the EXACT same PID 5500 with a DIFFERENT creation time!
        nativeOps.Register(5500, 133800000000020000L, pathB);
        snapshot = new List<(int Pid, string Name)> { (5500, "proc_b") };

        monitor.PollNewProcessesOnce();
        // Second poll with same proc_b must NOT emit a duplicate event!
        monitor.PollNewProcessesOnce();

        var hit = Assert.Single(observed);
        Assert.Equal(5500, hit.Pid);
        Assert.Equal("proc_b", hit.Name);
        Assert.Equal(pathB, hit.Path);
    }

    [Fact]
    public void P2_R5_BrowserShortcutRepair_PreservesBenignProfileArgs_AndNeverQuarantinesOnBackupOrSaveFailure()
    {
        var procCtrl = new ProcessController();
        var quarantine = new QuarantineManager(_tempRoot);
        var auditLog = new AuditLogService(_tempRoot);

        // 1. Happy path: preserve --profile-directory="Profile 2", --lang=ko AND user startup URL, strip ONLY malicious flags!
        var chromeExe = Path.Combine(_tempRoot, "chrome.exe");
        File.WriteAllText(chromeExe, "fake-chrome");
        var shortcutPath = Path.Combine(_tempRoot, "Google Chrome.lnk");
        File.WriteAllText(shortcutPath, "fake-lnk-bytes");

        string? savedArgs = null;
        var remediationOk = new MalwareRemediationService(
            procCtrl,
            quarantine,
            auditLog,
            _tempRoot,
            shortcutReaderOverride: _ => (
                true,
                chromeExe,
                "--profile-directory=\"Profile 2\" --lang=ko https://portal.school.edu/home --load-extension=\"C:\\Temp\\evil_ext\" --remote-debugging-port=9222 --proxy-server=http://1.2.3.4:8080",
                string.Empty),
            shortcutWriterOverride: (_, newArgs) =>
            {
                savedArgs = newArgs;
                return (true, string.Empty);
            });

        var shortcutItem = new MalwareThreatItem
        {
            Stage = MalwareScanStage.BrowserHijack,
            ThreatName = "Hijacker.Browser.ShortcutInjection",
            Severity = ThreatSeverity.Critical,
            RiskScore = 90,
            TargetPath = shortcutPath,
            ActionType = RemediationActionType.CleanBrowserShortcut
        };

        var okRes = remediationOk.CureSingleItem(shortcutItem);
        Assert.True(okRes.Success);
        Assert.Equal(SecurityActionTaken.RolledBack, okRes.ActionTaken);
        Assert.NotNull(savedArgs);
        Assert.Contains("--profile-directory=\"Profile 2\"", savedArgs!, StringComparison.Ordinal);
        Assert.Contains("--lang=ko", savedArgs!, StringComparison.Ordinal);
        Assert.Contains("https://portal.school.edu/home", savedArgs!, StringComparison.Ordinal);
        Assert.DoesNotContain("--load-extension", savedArgs!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("--remote-debugging-port", savedArgs!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("--proxy-server", savedArgs!, StringComparison.OrdinalIgnoreCase);
        Assert.True(File.Exists(shortcutPath));
        Assert.Empty(quarantine.ListEntries());

        // 2. Save failure must return failure and preserve original shortcut (NEVER fall through to Quarantine!)
        var remediationSaveFail = new MalwareRemediationService(
            procCtrl,
            quarantine,
            auditLog,
            _tempRoot,
            shortcutReaderOverride: _ => (true, chromeExe, "--profile-directory=\"Profile 1\" --load-extension=\"C:\\Temp\\evil\"", string.Empty),
            shortcutWriterOverride: (_, _) => (false, "Access denied saving shortcut"));

        var saveFailRes = remediationSaveFail.CureSingleItem(shortcutItem);
        Assert.False(saveFailRes.Success);
        Assert.Equal(SecurityActionTaken.Logged, saveFailRes.ActionTaken);
        Assert.True(File.Exists(shortcutPath));
        Assert.Empty(quarantine.ListEntries());

        // 3. Backup failure must return failure and preserve original shortcut (NEVER fall through to Quarantine!)
        var remediationBackupFail = new MalwareRemediationService(
            procCtrl,
            quarantine,
            auditLog,
            _tempRoot,
            shortcutBackupOverride: (_, _) => throw new IOException("Simulated disk full during shortcut backup"),
            shortcutReaderOverride: _ => (true, chromeExe, "--profile-directory=\"Profile 1\" --load-extension=\"C:\\Temp\\evil\"", string.Empty),
            shortcutWriterOverride: (_, _) => (true, string.Empty));

        var backupFailRes = remediationBackupFail.CureSingleItem(shortcutItem);
        Assert.False(backupFailRes.Success);
        Assert.Equal(SecurityActionTaken.Logged, backupFailRes.ActionTaken);
        Assert.True(File.Exists(shortcutPath));
        Assert.Empty(quarantine.ListEntries());
    }

    [Fact]
    public void P1_R6_ScheduledTaskRemediation_ArgumentsChangedSinceScan_MustHoldDeleteAndQuarantine_AndAllowExactMatch()
    {
        var taskBin = Path.Combine(_tempRoot, "updater_task.exe");
        File.WriteAllText(taskBin, "task-binary-v1");
        var taskBinSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(taskBin)));

        string BuildTaskXml(string args, string userId = "S-1-5-18", string trigger = "<LogonTrigger><Enabled>true</Enabled></LogonTrigger>") =>
            $"""
            <?xml version="1.0" encoding="UTF-16"?>
            <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <Triggers>{trigger}</Triggers>
              <Principals><Principal id="Author"><UserId>{userId}</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
              <Actions Context="Author"><Exec><Command>{taskBin}</Command><Arguments>{args}</Arguments></Exec></Actions>
            </Task>
            """;

        var scannedXml = BuildTaskXml("-w hidden -enc BADPAYLOAD");
        var reformattedSameXml = $"<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\" version=\"1.2\"><Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers><Principals><Principal id=\"Author\"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Actions Context=\"Author\"><Exec><Command>{taskBin}</Command><Arguments>-w hidden -enc BADPAYLOAD</Arguments></Exec></Actions></Task>";
        var changedArgsXml = BuildTaskXml("--normal-update-check");
        var changedPrincipalXml = BuildTaskXml("-w hidden -enc BADPAYLOAD", userId: "S-1-5-21-9999");
        var changedTriggerXml = BuildTaskXml("-w hidden -enc BADPAYLOAD", trigger: "<BootTrigger><Enabled>true</Enabled></BootTrigger>");

        const string taskPath = @"\VendorSuite\AutoUpdater";
        var scannedHash = PersistenceMonitor.ComputeScheduledTaskDefinitionSha256(taskPath, scannedXml);
        Assert.NotEmpty(scannedHash);
        // Formatting / attribute order changes must yield the exact same canonical hash
        Assert.Equal(scannedHash, PersistenceMonitor.ComputeScheduledTaskDefinitionSha256(taskPath, reformattedSameXml));
        // Any change in arguments, principal, or trigger MUST yield a different hash
        Assert.NotEqual(scannedHash, PersistenceMonitor.ComputeScheduledTaskDefinitionSha256(taskPath, changedArgsXml));
        Assert.NotEqual(scannedHash, PersistenceMonitor.ComputeScheduledTaskDefinitionSha256(taskPath, changedPrincipalXml));
        Assert.NotEqual(scannedHash, PersistenceMonitor.ComputeScheduledTaskDefinitionSha256(taskPath, changedTriggerXml));

        var procCtrl = new ProcessController();
        var quarantine = new QuarantineManager(_tempRoot);
        var auditLog = new AuditLogService(_tempRoot);

        int deleteCalls = 0;
        string currentLiveXml = changedArgsXml;
        bool failLiveRead = false;

        var remediation = new MalwareRemediationService(
            procCtrl,
            quarantine,
            auditLog,
            _tempRoot,
            commandRunnerOverride: (exe, args) =>
            {
                if (exe.Equals("schtasks.exe", StringComparison.OrdinalIgnoreCase))
                {
                    deleteCalls++;
                }
                return (true, string.Empty);
            },
            scheduledTaskDefinitionReaderOverride: _ =>
                failLiveRead
                    ? (false, string.Empty, "Access denied reading Task XML")
                    : (true, currentLiveXml, string.Empty));

        var taskThreat = new MalwareThreatItem
        {
            Stage = MalwareScanStage.PersistenceAndService,
            ThreatName = "Trojan.Persistence.MaliciousCommand",
            Severity = ThreatSeverity.Critical,
            RiskScore = 90,
            TargetPath = @"C:\Windows\System32\Tasks",
            EntryName = taskPath,
            AssociatedFilePath = taskBin,
            AssociatedFileSha256 = taskBinSha256,
            ScheduledTaskDefinitionSha256 = scannedHash,
            ActionType = RemediationActionType.DeleteScheduledTask
        };

        // 1. Only <Arguments> changed since scan -> 0 delete calls, 0 quarantine calls, must require re-scan!
        var changedRes = remediation.CureSingleItem(taskThreat);
        Assert.Equal(0, deleteCalls);
        Assert.False(changedRes.Success);
        Assert.Equal(false, changedRes.ScheduledTaskDeleted);
        Assert.Contains("재검사", changedRes.Message, StringComparison.Ordinal);
        Assert.True(File.Exists(taskBin));
        Assert.Empty(quarantine.ListEntries());

        // 2. Live definition read failure -> 0 delete calls, 0 quarantine calls, must require re-scan!
        failLiveRead = true;
        var readFailRes = remediation.CureSingleItem(taskThreat);
        Assert.Equal(0, deleteCalls);
        Assert.False(readFailRes.Success);
        Assert.Equal(false, readFailRes.ScheduledTaskDeleted);
        Assert.Contains("재검사", readFailRes.Message, StringComparison.Ordinal);
        Assert.True(File.Exists(taskBin));
        Assert.Empty(quarantine.ListEntries());

        // 3. Missing scan-time ScheduledTaskDefinitionSha256 -> 0 delete calls, 0 quarantine calls!
        failLiveRead = false;
        currentLiveXml = scannedXml;
        var missingHashRes = remediation.CureSingleItem(taskThreat with { ScheduledTaskDefinitionSha256 = null });
        Assert.Equal(0, deleteCalls);
        Assert.False(missingHashRes.Success);
        Assert.Equal(false, missingHashRes.ScheduledTaskDeleted);
        Assert.Contains("재검사", missingHashRes.Message, StringComparison.Ordinal);
        Assert.True(File.Exists(taskBin));
        Assert.Empty(quarantine.ListEntries());

        // 4. Exact definition match (even reformatted XML) -> deletes task & quarantines verified associated file cleanly!
        currentLiveXml = reformattedSameXml;
        var okRes = remediation.CureSingleItem(taskThreat);
        Assert.Equal(1, deleteCalls);
        Assert.True(okRes.Success);
        Assert.Equal(true, okRes.ScheduledTaskDeleted);
        Assert.Equal(QuarantineDisposition.RemovedImmediately, okRes.FileQuarantineDisposition);
        Assert.Equal(SecurityActionTaken.Quarantined, okRes.ActionTaken);
        Assert.False(File.Exists(taskBin));
        Assert.Single(quarantine.ListEntries());
    }

    [Fact]
    public void P2_R7_BrowserShortcutInspectionAndRepair_PreservesExternalUrlOnly_StripsOnlyRiskyFlags_AndHoldsOnTargetChange()
    {
        var chromeExe = @"C:\Program Files\Google\Chrome\Application\chrome.exe";
        var edgeExe = @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe";

        // 1. Dangerous string ONLY in Description / IconLocation (NOT in Arguments) -> must NOT trigger detection!
        var benignIconDescLnk = Path.Combine(_tempRoot, "BenignIconDesc.lnk");
        File.WriteAllBytes(benignIconDescLnk, ShellLinkParser.BuildSimpleShortcutBytes(
            targetPath: chromeExe,
            arguments: "--profile-directory=\"Default\"",
            description: "Docs about --load-extension and https://company-portal.example",
            iconLocation: @"C:\Tools\--load-extension\icon.ico"));
        Assert.Null(MzkDeepScanner.InspectBrowserShortcutHijack(benignIconDescLnk));

        // 2. External URL ONLY (e.g., intranet / school portal shortcut) -> excluded from recommended cure & NEVER modified!
        var portalOnlyLnk = Path.Combine(_tempRoot, "SchoolPortal.lnk");
        var portalArgs = "--profile-directory=\"Profile 1\" https://portal.university.edu/sso";
        File.WriteAllBytes(portalOnlyLnk, ShellLinkParser.BuildSimpleShortcutBytes(
            targetPath: chromeExe,
            arguments: portalArgs));

        var portalFinding = MzkDeepScanner.InspectBrowserShortcutHijack(portalOnlyLnk);
        Assert.NotNull(portalFinding);
        Assert.False(portalFinding!.RecommendedForCure);
        Assert.Equal(RemediationActionType.ManualReview, portalFinding.ActionType);

        var procCtrl = new ProcessController();
        var quarantine = new QuarantineManager(_tempRoot);
        var auditLog = new AuditLogService(_tempRoot);

        int portalWriteCalls = 0;
        var portalRemediation = new MalwareRemediationService(
            procCtrl,
            quarantine,
            auditLog,
            _tempRoot,
            shortcutReaderOverride: _ => (true, chromeExe, portalArgs, string.Empty),
            shortcutWriterOverride: (_, _) => { portalWriteCalls++; return (true, string.Empty); });

        // ManualReview item -> 0 write calls, original untouched
        var portalCureRes = portalRemediation.CureSingleItem(portalFinding);
        Assert.Equal(0, portalWriteCalls);
        Assert.False(portalCureRes.Success);
        // Even if forced through CleanBrowserShortcut -> 0 write calls, original untouched!
        var forcedPortalRes = portalRemediation.CureSingleItem(portalFinding with { ActionType = RemediationActionType.CleanBrowserShortcut });
        Assert.Equal(0, portalWriteCalls);
        Assert.True(forcedPortalRes.Success);
        Assert.True(File.Exists(portalOnlyLnk));
        Assert.Empty(quarantine.ListEntries());

        // 3. Normal external URL + Profile + Risky Flags -> scan records risky tokens, cure removes ONLY risky flags & values!
        var mixedLnk = Path.Combine(_tempRoot, "WorkPortalHijacked.lnk");
        var mixedArgs = "--profile-directory=\"Profile 2\" https://intranet.company.example/home --load-extension=\"C:\\Temp\\evil_ext\" --remote-debugging-port 9222";
        File.WriteAllBytes(mixedLnk, ShellLinkParser.BuildSimpleShortcutBytes(
            targetPath: chromeExe,
            arguments: mixedArgs));

        var mixedFinding = MzkDeepScanner.InspectBrowserShortcutHijack(mixedLnk);
        Assert.NotNull(mixedFinding);
        Assert.True(mixedFinding!.RecommendedForCure);
        Assert.Equal(RemediationActionType.CleanBrowserShortcut, mixedFinding.ActionType);
        Assert.Equal(chromeExe, mixedFinding.ShortcutTargetPathAtScan);
        Assert.Equal(mixedArgs, mixedFinding.ShortcutArgumentsAtScan);
        Assert.NotNull(mixedFinding.ShortcutRiskyTokensAtScan);
        Assert.Equal(2, mixedFinding.ShortcutRiskyTokensAtScan!.Count);

        int mixedWriteCalls = 0;
        string? writtenMixedArgs = null;
        var mixedRemediation = new MalwareRemediationService(
            procCtrl,
            quarantine,
            auditLog,
            _tempRoot,
            shortcutReaderOverride: _ => (true, chromeExe, mixedArgs, string.Empty),
            shortcutWriterOverride: (_, newArgs) =>
            {
                mixedWriteCalls++;
                writtenMixedArgs = newArgs;
                return (true, string.Empty);
            });

        var mixedCureRes = mixedRemediation.CureSingleItem(mixedFinding);
        Assert.True(mixedCureRes.Success);
        Assert.Equal(1, mixedWriteCalls);
        Assert.Equal(SecurityActionTaken.RolledBack, mixedCureRes.ActionTaken);
        Assert.Equal("--profile-directory=\"Profile 2\" https://intranet.company.example/home", writtenMixedArgs);
        Assert.True(File.Exists(mixedLnk));
        Assert.Empty(quarantine.ListEntries());

        // 4. User changed TargetPath after scan -> 0 write calls, 0 quarantine calls, original preserved, re-scan required!
        int targetChangedWriteCalls = 0;
        var targetChangedRemediation = new MalwareRemediationService(
            procCtrl,
            quarantine,
            auditLog,
            _tempRoot,
            shortcutReaderOverride: _ => (true, edgeExe, mixedArgs, string.Empty),
            shortcutWriterOverride: (_, _) => { targetChangedWriteCalls++; return (true, string.Empty); });

        var targetChangedRes = targetChangedRemediation.CureSingleItem(mixedFinding);
        Assert.Equal(0, targetChangedWriteCalls);
        Assert.False(targetChangedRes.Success);
        Assert.Equal(SecurityActionTaken.Logged, targetChangedRes.ActionTaken);
        Assert.Contains("재검사", targetChangedRes.Message, StringComparison.Ordinal);
        Assert.True(File.Exists(mixedLnk));
        Assert.Empty(quarantine.ListEntries());
    }

    [Fact]
    public void P1_R8_CodeReviewFixes_ShellLinkAnsiRelativePidl_ArgPairing_PartialQuarantineAudit_AndTaskDots()
    {
        // 1. P1: Non-Unicode (0x1C ANSI LinkInfo) Korean path decodes via Win32 CP_ACP (NOT UTF-8 Encoding.Default!)
        var koreanTarget = @"C:\Users\홍길동\AppData\Local\Google\Chrome\Application\chrome.exe";
        var ansiLnkPath = Path.Combine(_tempRoot, "KoreanAnsiLink.lnk");
        File.WriteAllBytes(ansiLnkPath, BuildAnsiOnlyLinkInfoShortcutBytes(koreanTarget, "--load-extension=\"C:\\Temp\\bad\""));
        Assert.True(ShellLinkParser.TryParseFile(ansiLnkPath, out var parsedAnsi));
        Assert.Equal(koreanTarget, parsedAnsi!.TargetPath);
        var ansiFinding = MzkDeepScanner.InspectBrowserShortcutHijack(ansiLnkPath);
        Assert.NotNull(ansiFinding);
        Assert.Equal(koreanTarget, ansiFinding!.ShortcutTargetPathAtScan);

        // 2. P1: RelativePath-only shortcut resolves against .lnk directory so scan vs COM TargetPath matches!
        var nestedDir = Directory.CreateDirectory(Path.Combine(_tempRoot, "sub", "links")).FullName;
        var expectedResolvedChrome = Path.GetFullPath(Path.Combine(_tempRoot, "browser", "chrome.exe"));
        var relLnkPath = Path.Combine(nestedDir, "RelativeChrome.lnk");
        File.WriteAllBytes(relLnkPath, BuildRelativeOnlyShortcutBytes(@"..\..\browser\chrome.exe", "--remote-debugging-port=9222"));
        Assert.True(ShellLinkParser.TryParseFile(relLnkPath, out var parsedRel));
        Assert.Equal(expectedResolvedChrome, parsedRel!.TargetPath);

        // 3. P2: PIDL-only shortcut (LinkInfo absent, TargetPath empty in binary) resolves target via fallback ONLY when risky args exist
        var pidlLnkPath = Path.Combine(_tempRoot, "PidlOnlyHijacked.lnk");
        File.WriteAllBytes(pidlLnkPath, BuildPidlOnlyShortcutBytes("--profile-directory=\"Default\" --load-extension=\"C:\\Temp\\evil\""));
        int fallbackInvocations = 0;
        var pidlFinding = MzkDeepScanner.InspectBrowserShortcutHijack(
            pidlLnkPath,
            pidlTargetFallbackOverride: _ =>
            {
                fallbackInvocations++;
                return (true, @"C:\Program Files\Google\Chrome\Application\chrome.exe", "--profile-directory=\"Default\" --load-extension=\"C:\\Temp\\evil\"", string.Empty);
            });
        Assert.Equal(1, fallbackInvocations);
        Assert.NotNull(pidlFinding);
        Assert.Equal(RemediationActionType.CleanBrowserShortcut, pidlFinding!.ActionType);

        // Benign PIDL-only shortcut without risky args or URLs must NOT invoke COM fallback at all!
        var benignPidlLnk = Path.Combine(_tempRoot, "PidlOnlyBenign.lnk");
        File.WriteAllBytes(benignPidlLnk, BuildPidlOnlyShortcutBytes("--profile-directory=\"Default\""));
        Assert.Null(MzkDeepScanner.InspectBrowserShortcutHijack(
            benignPidlLnk,
            pidlTargetFallbackOverride: _ =>
            {
                fallbackInvocations++;
                return (true, @"C:\Program Files\Google\Chrome\Application\chrome.exe", "--profile-directory=\"Default\"", string.Empty);
            }));
        Assert.Equal(1, fallbackInvocations);

        // 4. P2: Value-less dangerous flag immediately before user startup URL must NOT swallow the user's URL!
        var (cleaned1, removed1) = MalwareRemediationService.SanitizeBrowserShortcutArguments(
            "--profile-directory=\"Profile 1\" --remote-debugging-port https://portal.school.edu/sso");
        Assert.Equal("--profile-directory=\"Profile 1\" https://portal.school.edu/sso", cleaned1);
        Assert.Single(removed1);

        var (cleaned2, removed2) = MalwareRemediationService.SanitizeBrowserShortcutArguments(
            "-load-extension https://intranet.company.example/home --lang=ko");
        Assert.Equal("https://intranet.company.example/home --lang=ko", cleaned2);
        Assert.Single(removed2);

        // 5. P2: Scheduled task delete FAILS while associated file IS quarantined (RemovedImmediately) -> audit must record Quarantined!
        var taskBin = Path.Combine(_tempRoot, "task_partial_fail.exe");
        File.WriteAllText(taskBin, "malicious-task-binary");
        var taskBinSha = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(taskBin)));
        var taskXml = $"""
            <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <Actions Context="Author"><Exec><Command>{taskBin}</Command><Arguments>-enc AAAA</Arguments></Exec></Actions>
            </Task>
            """;
        var taskHash = PersistenceMonitor.ComputeScheduledTaskDefinitionSha256(@"\Vendor\PartialFailTask", taskXml);

        var quarantine = new QuarantineManager(_tempRoot);
        var auditLog = new AuditLogService(_tempRoot);
        var remediation = new MalwareRemediationService(
            new ProcessController(),
            quarantine,
            auditLog,
            _tempRoot,
            commandRunnerOverride: (_, _) => (false, "ACCESS_DENIED"),
            scheduledTaskDefinitionReaderOverride: _ => (true, taskXml, string.Empty));

        var partialRes = remediation.CureSingleItem(new MalwareThreatItem
        {
            Stage = MalwareScanStage.PersistenceAndService,
            ThreatName = "Trojan.Persistence.PartialFail",
            Severity = ThreatSeverity.Critical,
            RiskScore = 90,
            TargetPath = @"C:\Windows\System32\Tasks",
            EntryName = @"\Vendor\PartialFailTask",
            AssociatedFilePath = taskBin,
            AssociatedFileSha256 = taskBinSha,
            ScheduledTaskDefinitionSha256 = taskHash,
            ActionType = RemediationActionType.DeleteScheduledTask
        });

        Assert.False(partialRes.Success);
        Assert.Equal(false, partialRes.ScheduledTaskDeleted);
        Assert.Equal(QuarantineDisposition.RemovedImmediately, partialRes.FileQuarantineDisposition);
        Assert.Equal(SecurityActionTaken.Quarantined, partialRes.ActionTaken);
        Assert.False(File.Exists(taskBin));
        Assert.Single(quarantine.ListEntries());
        Assert.Equal(SecurityActionTaken.Quarantined, auditLog.LoadRecentEvents(5).Single().ActionTaken);

        // 6. P3: Task name containing consecutive dots ("App..Updater") is NOT falsely rejected as path traversal, while "\..\evil" IS rejected
        PersistenceMonitor.TryReadScheduledTaskXmlFromDisk(@"\Vendor\App..Updater", out _, out var dotNameErr);
        Assert.DoesNotContain("유효하지 않은", dotNameErr, StringComparison.Ordinal);
        Assert.False(PersistenceMonitor.TryReadScheduledTaskXmlFromDisk(@"\Vendor\..\OutsideTask", out _, out var traversalErr));
        Assert.Contains("유효하지 않은", traversalErr, StringComparison.Ordinal);
    }

    private static byte[] BuildAnsiOnlyLinkInfoShortcutBytes(string ansiTargetPath, string arguments)
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms, Encoding.Unicode, leaveOpen: true);
        byte[] clsid = { 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 };
        uint flags = 0x02u | 0x20u | 0x80u; // HasLinkInfo | HasArguments | IsUnicode
        bw.Write(0x4Cu);
        bw.Write(clsid);
        bw.Write(flags);
        bw.Write(new byte[76 - 24]);

        var ansiBytes = ShellLinkParser.EncodeWindowsAnsi(ansiTargetPath).Concat(new byte[] { 0 }).ToArray();
        const uint headerSize = 0x1Cu; // 28-byte ANSI-only LinkInfo header (no Unicode offsets!)
        uint localBasePathOffset = headerSize;
        uint commonSuffixOffset = localBasePathOffset + (uint)ansiBytes.Length;
        uint linkInfoSize = commonSuffixOffset + 1;
        bw.Write(linkInfoSize);
        bw.Write(headerSize);
        bw.Write(1u); // VolumeIDAndLocalBasePath
        bw.Write(0u);
        bw.Write(localBasePathOffset);
        bw.Write(0u);
        bw.Write(commonSuffixOffset);
        bw.Write(ansiBytes);
        bw.Write((byte)0);

        bw.Write((ushort)arguments.Length);
        bw.Write(Encoding.Unicode.GetBytes(arguments));
        bw.Write(0u);
        bw.Flush();
        return ms.ToArray();
    }

    private static byte[] BuildRelativeOnlyShortcutBytes(string relativePath, string arguments)
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms, Encoding.Unicode, leaveOpen: true);
        byte[] clsid = { 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 };
        uint flags = 0x08u | 0x20u | 0x80u; // HasRelativePath | HasArguments | IsUnicode
        bw.Write(0x4Cu);
        bw.Write(clsid);
        bw.Write(flags);
        bw.Write(new byte[76 - 24]);

        bw.Write((ushort)relativePath.Length);
        bw.Write(Encoding.Unicode.GetBytes(relativePath));
        bw.Write((ushort)arguments.Length);
        bw.Write(Encoding.Unicode.GetBytes(arguments));
        bw.Write(0u);
        bw.Flush();
        return ms.ToArray();
    }

    private static byte[] BuildPidlOnlyShortcutBytes(string arguments)
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms, Encoding.Unicode, leaveOpen: true);
        byte[] clsid = { 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 };
        uint flags = 0x01u | 0x20u | 0x80u; // HasLinkTargetIDList | HasArguments | IsUnicode (no LinkInfo!)
        bw.Write(0x4Cu);
        bw.Write(clsid);
        bw.Write(flags);
        bw.Write(new byte[76 - 24]);

        // Minimal dummy IDList (2-byte terminal 0x0000)
        bw.Write((ushort)2);
        bw.Write((ushort)0);

        bw.Write((ushort)arguments.Length);
        bw.Write(Encoding.Unicode.GetBytes(arguments));
        bw.Write(0u);
        bw.Flush();
        return ms.ToArray();
    }
}
