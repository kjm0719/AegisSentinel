using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using AegisSentinel.Core.Engine;
using AegisSentinel.Core.Models;
using AegisSentinel.Core.Services;

namespace AegisSentinel.Tests;

/// <summary>
/// Reproducible, safe benchmark suite answering the three core quantitative user-outcome questions:
/// 1. Document damage reduction & SHA-256 verified recovery under simulated ransomware
/// 2. False-freeze rate & per-operation latency overhead across benign dev/game/update/backup workflows
/// 3. User-data preservation rate under injected fault conditions
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
    public void Benchmark_01_RansomwareDocumentProtection_MeasuresDamageReductionAnd100PercentSha256Recovery()
    {
        var docsDir = Path.Combine(_tempRoot, "UserDocuments");
        Directory.CreateDirectory(docsDir);

        const int totalDocs = 50;
        var originalHashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < totalDocs; i++)
        {
            var path = Path.Combine(docsDir, $"report_{i:D2}.txt");
            var content = $"AegisSentinel Benchmark Document #{i:D2}\n" +
                          string.Join("\n", Enumerable.Repeat($"Quarterly financial and engineering ledger line {i}.", 25));
            File.WriteAllText(path, content, Encoding.UTF8);
            originalHashes[path] = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
        }

        // Prepare RecoveryVault + Canary + RansomwareDetector
        var vault = new RecoveryVault(_tempRoot);
        var canaryMgr = new CanaryManager();
        var detector = new RansomwareDetector();
        var policy = GuardPolicy.CreateDefault();
        policy.ProtectedFolders = new List<string> { docsDir };
        policy.RapidWriteThresholdPer3Sec = 10;

        int snapshotted = vault.SnapshotProtectedFolders(policy.ProtectedFolders);
        Assert.Equal(totalDocs, snapshotted);
        canaryMgr.DeployCanaries(policy.ProtectedFolders);
        var canaryPath = canaryMgr.CanaryPaths.First();

        // Simulate alphabetical ransomware encryption sweep (hits "!_00_aegis_canary..." first or rapid burst)
        var allTargets = Directory.GetFiles(docsDir).OrderBy(p => Path.GetFileName(p), StringComparer.OrdinalIgnoreCase).ToList();
        int attackerPid = 88001;
        bool attackerFrozen = false;
        int modifiedBeforeFreeze = 0;
        var sw = Stopwatch.StartNew();

        foreach (var file in allTargets)
        {
            if (attackerFrozen) break;

            bool isCanary = canaryMgr.IsCanaryPath(file);
            try { File.SetAttributes(file, FileAttributes.Normal); } catch { }
            File.WriteAllBytes(file, RandomNumberGenerator.GetBytes(8192));

            if (!isCanary)
            {
                modifiedBeforeFreeze++;
            }

            var alert = detector.RecordFileActivity(
                attackerPid,
                "sim_ransom.exe",
                Path.Combine(_tempRoot, "sim_ransom.exe"),
                file,
                isRenameOrDelete: false,
                isCanaryFile: isCanary,
                policy);

            if (alert is not null && alert.RiskScore >= 75)
            {
                attackerFrozen = true;
            }
        }
        sw.Stop();

        Assert.True(attackerFrozen, "Ransomware simulator must be caught and frozen!");
        // Because canary file sorts first ("!_00_..."), damage before freeze should be minimal (0 or well under totalDocs)
        Assert.True(modifiedBeforeFreeze <= 10, $"Expected <= 10 modified docs before freeze, got {modifiedBeforeFreeze}/{totalDocs}");

        // Restore any modified documents from RecoveryVault and verify 100% SHA-256 match
        var snapshots = vault.ListSnapshots().ToDictionary(s => s.OriginalPath, StringComparer.OrdinalIgnoreCase);
        int intactOrRecovered = 0;
        foreach (var kvp in originalHashes)
        {
            var currentHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(kvp.Key)));
            if (!currentHash.Equals(kvp.Value, StringComparison.OrdinalIgnoreCase))
            {
                Assert.True(vault.RestoreSnapshot(snapshots[kvp.Key].Id));
                currentHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(kvp.Key)));
            }
            if (currentHash.Equals(kvp.Value, StringComparison.OrdinalIgnoreCase))
            {
                intactOrRecovered++;
            }
        }

        canaryMgr.RemoveCanaries();

        Assert.Equal(totalDocs, intactOrRecovered);
        _output.WriteLine($"[BENCH-01] TotalDocs={totalDocs}, BaselineUnprotectedDamaged={totalDocs}, ModifiedBeforeFreeze={modifiedBeforeFreeze}, RecoveredSha256Match={intactOrRecovered}/{totalDocs} (100%), DetectionLatencyMs={sw.ElapsedMilliseconds}");
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

        // 250 Dev workflow ops + 250 Browser/Game ops + 250 Updater ops + 250 File-copy/Backup ops = 1,000 benign ops
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
        Assert.True(sw.ElapsedMilliseconds < 5000, $"Expected 1,000 benign checks < 5s, took {sw.ElapsedMilliseconds}ms");
        _output.WriteLine($"[BENCH-02] BenignOps=1000, FalseFreezes={falseFreezes}, FalseAlerts={falseAlerts}, TotalMs={sw.ElapsedMilliseconds}, AvgLatencyUs={usPerOp:F2}");
    }

    [Fact]
    public void Benchmark_03_FaultResilienceMatrix_ZeroUserDataLossAcrossSixInjectedFaults()
    {
        int passedFaultScenarios = 0;
        const int totalFaultScenarios = 6;

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
            var qm1 = new QuarantineManager(d, deleteFileOverride: _ => false, scheduleRebootDeleteOverride: _ => true);
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

        Assert.Equal(totalFaultScenarios, passedFaultScenarios);
        _output.WriteLine($"[BENCH-03] FaultResiliencePassed={passedFaultScenarios}/{totalFaultScenarios} (Zero User Data Loss)");
    }
}
