using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using AegisSentinel.Core.Engine;
using AegisSentinel.Core.Models;
using AegisSentinel.Core.Services;

namespace AegisSentinel.Tests;

/// <summary>
/// Reproducible, safe benchmark suite answering three core quantitative questions:
/// 1A. Canary-first rule-reaction unit baseline (in-process detector reaction, no OS freeze)
/// 1B. Real separate-process ransomware A/B comparison (same temp-doc mutator process run BEFORE vs WITH live SecurityOrchestrator + Win32 NtSuspendProcess + RecoveryVault)
/// 2. False-freeze rate & per-operation latency overhead across 1,000 benign operations
/// 3. User-data preservation rate across 7 injected fault conditions
/// </summary>
public sealed class RansomwareDefenseBenchmarkTests : IDisposable
{
    private readonly string _tempRoot;
    private readonly Xunit.Abstractions.ITestOutputHelper _output;

    public RansomwareDefenseBenchmarkTests(Xunit.Abstractions.ITestOutputHelper output)
    {
        _output = output;
        _tempRoot = Path.Combine(Path.GetTempPath(), $"AegisBench_{Guid.NewGuid():N}");
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

    [Fact]
    public void Benchmark_01A_CanaryFirstRuleReaction_UnitBaseline()
    {
        var docsDir = Path.Combine(_tempRoot, "CanaryUnitDocs");
        Directory.CreateDirectory(docsDir);

        const int totalDocs = 50;
        var originalHashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < totalDocs; i++)
        {
            var path = Path.Combine(docsDir, $"report_{i:D2}.txt");
            var content = $"AegisSentinel Rule Baseline Document #{i:D2}\n" +
                          string.Join("\n", Enumerable.Repeat($"Quarterly financial and engineering ledger line {i}.", 25));
            File.WriteAllText(path, content, Encoding.UTF8);
            originalHashes[path] = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
        }

        var vault = new RecoveryVault(_tempRoot);
        var canaryMgr = new CanaryManager();
        var detector = new RansomwareDetector();
        var policy = GuardPolicy.CreateDefault();
        policy.ProtectedFolders = new List<string> { docsDir };
        policy.RapidWriteThresholdPer3Sec = 10;

        Assert.Equal(totalDocs, vault.SnapshotProtectedFolders(policy.ProtectedFolders));
        canaryMgr.DeployCanaries(policy.ProtectedFolders);

        // Canary-first alphabetical rule-reaction test (in-process detector callback — NOT real OS freeze)
        var allTargets = Directory.GetFiles(docsDir).OrderBy(p => Path.GetFileName(p), StringComparer.OrdinalIgnoreCase).ToList();
        bool ruleTriggered = false;
        int modifiedBeforeRuleTrigger = 0;
        var sw = Stopwatch.StartNew();

        foreach (var file in allTargets)
        {
            if (ruleTriggered) break;
            bool isCanary = canaryMgr.IsCanaryPath(file);
            try { File.SetAttributes(file, FileAttributes.Normal); } catch { }
            File.WriteAllBytes(file, RandomNumberGenerator.GetBytes(8192));
            if (!isCanary) modifiedBeforeRuleTrigger++;

            var alert = detector.RecordFileActivity(
                88001, "sim_ransom.exe", Path.Combine(_tempRoot, "sim_ransom.exe"),
                file, isRenameOrDelete: false, isCanaryFile: isCanary, policy);
            if (alert is not null && alert.RiskScore >= 75) ruleTriggered = true;
        }
        sw.Stop();
        canaryMgr.RemoveCanaries();

        Assert.True(ruleTriggered);
        Assert.Equal(0, modifiedBeforeRuleTrigger);
        _output.WriteLine($"[BENCH-01A-RULE-ONLY] Scenario=CanaryFirstInProcessRuleReaction, TotalDocs={totalDocs}, ModifiedBeforeRuleTrigger={modifiedBeforeRuleTrigger}, RuleReactionMs={sw.ElapsedMilliseconds}");
    }

    [Fact]
    public async Task Benchmark_01B_RealSeparateProcessRansomware_BeforeAndAfterProtectionComparison()
    {
        // Real A/B comparison using an external separate OS child process (powershell.exe) mutating ONLY
        // isolated temp documents in the EXACT same deterministic order (doc_00.txt .. doc_19.txt, NO canary first!):
        //   Run A: Unprotected (AegisSentinel OFF) — measures actual damaged docs on disk
        //   Run B: Protected (live SecurityOrchestrator + FileSystemWatcher + Restart Manager + real Win32 NtSuspendProcess + RecoveryVault)
        const int totalDocs = 20;
        var unprotectedDir = Path.Combine(_tempRoot, "AB_UnprotectedDocs");
        var protectedDir = Path.Combine(_tempRoot, "AB_ProtectedDocs");
        var orchestratorDataDir = Path.Combine(_tempRoot, "AB_OrchData");
        Directory.CreateDirectory(unprotectedDir);
        Directory.CreateDirectory(protectedDir);
        Directory.CreateDirectory(orchestratorDataDir);

        static Dictionary<string, string> CreateTestDocs(string dir, int count)
        {
            var hashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < count; i++)
            {
                var path = Path.Combine(dir, $"doc_{i:D2}.txt");
                var text = $"AegisSentinel A/B Benchmark Document #{i:D2}\n" +
                           string.Join("\n", Enumerable.Repeat($"Original clean user contract paragraph {i}.", 30));
                File.WriteAllText(path, text, Encoding.UTF8);
                hashes[path] = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
            }
            return hashes;
        }

        static byte[] ReadFileBytesShared(string path)
        {
            for (int attempt = 0; attempt < 20; attempt++)
            {
                try
                {
                    using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    using var ms = new MemoryStream();
                    fs.CopyTo(ms);
                    return ms.ToArray();
                }
                catch (IOException) when (attempt < 19)
                {
                    Thread.Sleep(50);
                }
            }
            return File.ReadAllBytes(path);
        }

        static int CountModifiedDocs(Dictionary<string, string> originalHashes)
        {
            int modified = 0;
            foreach (var kvp in originalHashes)
            {
                var current = Convert.ToHexString(SHA256.HashData(ReadFileBytesShared(kvp.Key)));
                if (!current.Equals(kvp.Value, StringComparison.OrdinalIgnoreCase))
                {
                    modified++;
                }
            }
            return modified;
        }

        // Tiny isolated mutator script: touches ONLY doc_*.txt inside the passed temp directory in exact order,
        // holding each handle ~180 ms while encrypting so standard-mode Restart Manager attributes the live child PID.
        var scriptPath = Path.Combine(_tempRoot, "safe_temp_mutator.ps1");
        File.WriteAllText(scriptPath, """
            param([string]$TargetDir)
            $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            $buf = New-Object byte[] 8192
            $files = Get-ChildItem -Path $TargetDir -Filter 'doc_*.txt' | Sort-Object Name
            foreach ($f in $files) {
                $rng.GetBytes($buf)
                $fs = [System.IO.File]::Open($f.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
                try {
                    $fs.SetLength(0)
                    $fs.Write($buf, 0, $buf.Length)
                    $fs.Flush()
                    Start-Sleep -Milliseconds 180
                } finally {
                    $fs.Dispose()
                }
            }
            """, Encoding.UTF8);

        var powershellExe = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            @"WindowsPowerShell\v1.0\powershell.exe");
        Assert.True(File.Exists(powershellExe));

        ProcessStartInfo BuildMutatorPsi(string dir) => new(powershellExe, $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{scriptPath}\" -TargetDir \"{dir}\"")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        // --- Run A: Unprotected Baseline (actual separate OS process runs to completion) ---
        var unprotectedHashes = CreateTestDocs(unprotectedDir, totalDocs);
        var swUnprotected = Stopwatch.StartNew();
        using (var procA = Process.Start(BuildMutatorPsi(unprotectedDir))!)
        {
            Assert.True(procA.WaitForExit(15000), "Unprotected baseline mutator timed out!");
        }
        swUnprotected.Stop();
        int unprotectedModified = CountModifiedDocs(unprotectedHashes);
        Assert.Equal(totalDocs, unprotectedModified);

        // --- Run B: Live AegisSentinel Protection (real FileSystemWatcher + Restart Manager + Win32 NtSuspendProcess + RecoveryVault) ---
        var protectedHashes = CreateTestDocs(protectedDir, totalDocs);
        var store = new PolicyStore(orchestratorDataDir);
        var policy = GuardPolicy.CreateDefault();
        policy.Mode = ProtectionMode.Balanced;
        policy.EnableEtwTelemetry = false; // Standard-user safe live path (FSW + Restart Manager + real Win32 NtSuspendProcess)
        policy.DeployCanaryFiles = false;  // Disable canary-first shortcut so we measure pure behavioral burst freeze!
        policy.ProtectedFolders = new List<string> { protectedDir };
        policy.RapidWriteThresholdPer3Sec = 5;
        store.Save(policy);

        using var orchestrator = new SecurityOrchestrator(store);
        var frozenTcs = new TaskCompletionSource<SecurityEvent>(TaskCreationOptions.RunContinuationsAsynchronously);
        orchestrator.EventRecorded += evt =>
        {
            if (evt.Category == ThreatCategory.Ransomware && evt.IsProcessSuspended)
            {
                frozenTcs.TrySetResult(evt);
            }
        };

        orchestrator.Start();
        orchestrator.Vault.SnapshotProtectedFolders(policy.ProtectedFolders);
        Assert.Equal(totalDocs, orchestrator.Vault.ListSnapshots().Count(s => s.OriginalPath.StartsWith(protectedDir, StringComparison.OrdinalIgnoreCase)));

        Process? procB = null;
        int protectedModifiedBeforeFreeze;
        long freezeElapsedMs;
        int recoveredSha256Match = 0;

        try
        {
            var swProtected = Stopwatch.StartNew();
            procB = Process.Start(BuildMutatorPsi(protectedDir))!;

            // Wait for REAL OS NtSuspendProcess freeze of the live separate child process!
            var freezeEvt = await frozenTcs.Task.WaitAsync(TimeSpan.FromSeconds(12));
            swProtected.Stop();
            freezeElapsedMs = swProtected.ElapsedMilliseconds;

            Assert.Equal(procB.Id, freezeEvt.ProcessId);
            Assert.True(orchestrator.ProcessControl.IsProcessSuspendedByUs(procB.Id), "Live child process must be genuinely frozen by Win32 NtSuspendProcess!");

            // Confirm frozen process stopped mutating files (wait 450 ms > 2 write intervals)
            await Task.Delay(450);
            Assert.False(procB.HasExited, "Frozen child process should still be suspended in memory, not exited!");

            // Kill frozen mutator before measuring final protected state and restoring from RecoveryVault
            try
            {
                if (!procB.HasExited) procB.Kill(entireProcessTree: true);
                if (!procB.WaitForExit(5000))
                {
                    orchestrator.ProcessControl.TryTerminateProcess(procB.Id);
                    procB.WaitForExit(3000);
                }
            }
            catch { }
            orchestrator.Stop();

            protectedModifiedBeforeFreeze = CountModifiedDocs(protectedHashes);
            Assert.True(protectedModifiedBeforeFreeze < unprotectedModified,
                $"Expected live freeze to reduce damaged docs below unprotected baseline ({unprotectedModified}), got {protectedModifiedBeforeFreeze}!");

            // Restore every modified document from RecoveryVault and verify exact SHA-256 match
            var snapshots = orchestrator.Vault.ListSnapshots().ToDictionary(s => s.OriginalPath, StringComparer.OrdinalIgnoreCase);
            foreach (var kvp in protectedHashes)
            {
                var current = Convert.ToHexString(SHA256.HashData(ReadFileBytesShared(kvp.Key)));
                if (!current.Equals(kvp.Value, StringComparison.OrdinalIgnoreCase))
                {
                    Assert.True(orchestrator.Vault.RestoreSnapshot(snapshots[kvp.Key].Id));
                    current = Convert.ToHexString(SHA256.HashData(ReadFileBytesShared(kvp.Key)));
                }
                if (current.Equals(kvp.Value, StringComparison.OrdinalIgnoreCase))
                {
                    recoveredSha256Match++;
                }
            }
        }
        finally
        {
            orchestrator.ProcessControl.ResumeAllSuspendedProcesses();
            orchestrator.Stop();
            if (procB is not null)
            {
                try { if (!procB.HasExited) procB.Kill(entireProcessTree: true); procB.WaitForExit(2000); } catch { }
                procB.Dispose();
            }
        }

        Assert.Equal(totalDocs, recoveredSha256Match);
        _output.WriteLine(
            $"[BENCH-01B-REAL-PROC-AB] TotalDocs={totalDocs}, " +
            $"UnprotectedRunModified={unprotectedModified}/{totalDocs} ({swUnprotected.ElapsedMilliseconds}ms), " +
            $"ProtectedLiveFreezeModified={protectedModifiedBeforeFreeze}/{totalDocs} (FreezeAt={freezeElapsedMs}ms), " +
            $"SavedUnmodifiedBeforeFreeze={unprotectedModified - protectedModifiedBeforeFreeze}, " +
            $"RecoveredSha256Match={recoveredSha256Match}/{totalDocs} (100%)");
    }

    [Fact]
    public void Benchmark_02_NormalWorkflowOverhead_ZeroFalseFreezesAcross1000BenignOperations()
    {
        var policy = GuardPolicy.CreateDefault();
        var procEval = new ProcessRuleEvaluator();
        var risk = new BehaviorRiskEngine();
        var intel = new ThreatIntelStore(_tempRoot);
        var netGuard = new NetworkGuardMonitor(new ProcessController(), new SignatureVerifier(), risk, intel, () => policy);
        var ransom = new RansomwareDetector();

        int falseAlerts = 0;
        int falseFreezes = 0;
        var now = DateTimeOffset.UtcNow;
        var sw = Stopwatch.StartNew();

        for (int i = 0; i < 250; i++)
        {
            var devEvt = procEval.Evaluate(new ProcessEvaluationContext
            {
                ProcessId = 30000 + i,
                ProcessName = "dotnet",
                ProcessPath = @"C:\Program Files\dotnet\dotnet.exe",
                CommandLine = "dotnet build -c Release --no-incremental",
                ParentProcessId = 1500,
                ParentProcessName = "Code",
                ParentProcessPath = @"C:\Users\Dev\AppData\Local\Programs\Microsoft VS Code\Code.exe",
                Signature = new SignatureInfo(SignatureStatus.TrustedMicrosoft, "Microsoft Corporation")
            }, policy);
            if (devEvt is not null) { falseAlerts++; if (devEvt.RiskScore >= 75) falseFreezes++; }

            var netEvt = netGuard.EvaluateOutboundConnection(
                31000 + i, "chrome", @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                IPAddress.Parse("142.250.196.110"), 443, policy,
                new SignatureInfo(SignatureStatus.TrustedVendor, "Google LLC"),
                domainOverride: "github.com");
            if (netEvt is not null) { falseAlerts++; if (netEvt.RiskScore >= 75) falseFreezes++; }

            var scriptEvt = FilelessScriptGuard.AnalyzeScriptBlock("git status && dotnet test -c Release", 32000 + i, policy);
            if (scriptEvt is not null) { falseAlerts++; if (scriptEvt.RiskScore >= 75) falseFreezes++; }

            var copyEvt = ransom.RecordFileActivity(
                33000, "explorer", @"C:\Windows\explorer.exe",
                $@"C:\Users\Dev\Documents\backup_item_{i}.txt",
                isRenameOrDelete: false, isCanaryFile: false, policy, now.AddMilliseconds(i * 15), checkEntropy: false);
            if (copyEvt is not null) { falseAlerts++; if (copyEvt.RiskScore >= 75) falseFreezes++; }
        }

        sw.Stop();
        double usPerOp = (sw.Elapsed.TotalMilliseconds * 1000.0) / 1000.0;

        Assert.Equal(0, falseFreezes);
        Assert.Equal(0, falseAlerts);
        Assert.True(sw.ElapsedMilliseconds < 5000);
        _output.WriteLine($"[BENCH-02] BenignOps=1000, FalseFreezes={falseFreezes}, FalseAlerts={falseAlerts}, TotalMs={sw.ElapsedMilliseconds}, AvgLatencyUs={usPerOp:F2}");
    }

    [Fact]
    public void Benchmark_03_FaultResilienceMatrix_ZeroUserDataLossAcrossSevenInjectedFaults()
    {
        int passedFaultScenarios = 0;
        const int totalFaultScenarios = 7;

        // Fault 1: Disk-full metadata write failure -> original preserved untouched
        {
            var d = Path.Combine(_tempRoot, "f1");
            Directory.CreateDirectory(d);
            var f = Path.Combine(d, "a.exe");
            var b = Encoding.UTF8.GetBytes("FAULT-1-ORIGINAL");
            File.WriteAllBytes(f, b);
            var qm = new QuarantineManager(d, writeMetadataOverride: (_, _) => throw new IOException("Disk full"));
            Assert.Throws<IOException>(() => qm.QuarantineFile(f, "F1"));
            Assert.Equal(b, File.ReadAllBytes(f));
            passedFaultScenarios++;
        }

        // Fault 2: Hard interruption right after original delete -> restart reconciles & restores
        {
            var d = Path.Combine(_tempRoot, "f2");
            Directory.CreateDirectory(d);
            var f = Path.Combine(d, "b.exe");
            var b = Encoding.UTF8.GetBytes("FAULT-2-CRASH-RECOVER");
            File.WriteAllBytes(f, b);
            int w = 0;
            var qm = new QuarantineManager(d, writeMetadataOverride: (p, j) => { if (++w == 1) File.WriteAllText(p, j); else throw new IOException("Crash"); });
            var e = qm.QuarantineFile(f, "F2");
            var restarted = new QuarantineManager(d);
            var rec = Assert.Single(restarted.ListEntries(), x => x.Id == e.Id);
            Assert.True(restarted.RestoreFileDetailed(rec.Id).Success);
            Assert.Equal(b, File.ReadAllBytes(f));
            passedFaultScenarios++;
        }

        // Fault 3: Real OS exclusive lock on destination during overwrite restore -> locked file & backup intact
        {
            var d = Path.Combine(_tempRoot, "f3");
            Directory.CreateDirectory(d);
            var f = Path.Combine(d, "c.exe");
            var orig = Encoding.UTF8.GetBytes("FAULT-3-ORIG");
            File.WriteAllBytes(f, orig);
            var qm = new QuarantineManager(d);
            var e = qm.QuarantineFile(f, "F3");
            var lockedContent = Encoding.UTF8.GetBytes("FAULT-3-LOCKED-USER-FILE");
            File.WriteAllBytes(f, lockedContent);
            using (new FileStream(f, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                Assert.Equal(QuarantineRestoreStatus.WriteFailed, qm.RestoreFileDetailed(e.Id, overwriteExisting: true).Status);
                Assert.True(File.Exists(e.QuarantineFilePath));
            }
            Assert.Equal(lockedContent, File.ReadAllBytes(f));
            passedFaultScenarios++;
        }

        // Fault 4: Destination conflict -> default restore refuses overwrite and keeps both files
        {
            var d = Path.Combine(_tempRoot, "f4");
            Directory.CreateDirectory(d);
            var f = Path.Combine(d, "d.exe");
            File.WriteAllBytes(f, Encoding.UTF8.GetBytes("FAULT-4-ORIG"));
            var qm = new QuarantineManager(d);
            var e = qm.QuarantineFile(f, "F4");
            var newer = Encoding.UTF8.GetBytes("FAULT-4-NEWER");
            File.WriteAllBytes(f, newer);
            Assert.Equal(QuarantineRestoreStatus.DestinationConflict, qm.RestoreFileDetailed(e.Id, overwriteExisting: false).Status);
            Assert.Equal(newer, File.ReadAllBytes(f));
            Assert.True(File.Exists(e.QuarantineFilePath));
            passedFaultScenarios++;
        }

        // Fault 5: Reboot-delete cancellation failure -> quarantine copy preserved
        {
            var d = Path.Combine(_tempRoot, "f5");
            Directory.CreateDirectory(d);
            var f = Path.Combine(d, "e.exe");
            var orig = Encoding.UTF8.GetBytes("FAULT-5-REBOOT-CANCEL");
            File.WriteAllBytes(f, orig);
            var qm1 = new QuarantineManager(d, deleteFileOverride: _ => false);
            var e = qm1.QuarantineFile(f, "F5");
            File.Delete(f);
            var qm2 = new QuarantineManager(d, cancelRebootDeleteOverride: _ => false, isRebootDeleteScheduledOverride: _ => true);
            Assert.Equal(QuarantineRestoreStatus.RestoredButRebootDeleteCancelFailed, qm2.RestoreFileDetailed(e.Id).Status);
            Assert.True(File.Exists(e.QuarantineFilePath));
            passedFaultScenarios++;
        }

        // Fault 6: File growing past 64 MiB (configured threshold) mid-read -> spills to AEGISQ3 and restores byte-for-byte
        {
            var d = Path.Combine(_tempRoot, "f6");
            Directory.CreateDirectory(d);
            var f = Path.Combine(d, "f.exe");
            var p1 = RandomNumberGenerator.GetBytes(2048);
            var p2 = RandomNumberGenerator.GetBytes(6144);
            var expected = p1.Concat(p2).ToArray();
            File.WriteAllBytes(f, p1);
            bool grew = false;
            var qm = new QuarantineManager(d, maxInMemoryGcmBytes: 3072, chunkedGcmChunkSize: 2048, onAfterFirstReadChunkForTest: () =>
            {
                if (grew) return;
                grew = true;
                using var w = new FileStream(f, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                w.Write(p2, 0, p2.Length);
                w.Flush(true);
            });
            var e = qm.QuarantineFile(f, "F6");
            Assert.Equal(QuarantineRestoreStatus.Restored, qm.RestoreFileDetailed(e.Id).Status);
            Assert.Equal(expected, File.ReadAllBytes(f));
            passedFaultScenarios++;
        }

        // Fault 7: Original replaced with newer version right after copy saved -> new file preserved untouched
        {
            var d = Path.Combine(_tempRoot, "f7");
            Directory.CreateDirectory(d);
            var f = Path.Combine(d, "g.exe");
            File.WriteAllBytes(f, Encoding.UTF8.GetBytes("FAULT-7-OLD"));
            var newer = Encoding.UTF8.GetBytes("FAULT-7-NEW-REPLACED");
            bool swapped = false;
            var qm = new QuarantineManager(d, writeMetadataOverride: (p, j) =>
            {
                File.WriteAllText(p, j);
                if (!swapped)
                {
                    swapped = true;
                    var tmp = Path.Combine(d, "swap.tmp");
                    File.WriteAllBytes(tmp, newer);
                    File.Replace(tmp, f, null, true);
                }
            });
            var e = qm.QuarantineFile(f, "F7");
            Assert.Equal(QuarantineDisposition.OriginalChangedNotRemoved, e.Disposition);
            Assert.Equal(newer, File.ReadAllBytes(f));
            passedFaultScenarios++;
        }

        Assert.Equal(totalFaultScenarios, passedFaultScenarios);
        _output.WriteLine($"[BENCH-03] FaultResiliencePassed={passedFaultScenarios}/{totalFaultScenarios} (Zero User Data Loss)");
    }
}
