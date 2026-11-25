using System.Text.Json;

namespace AegisSentinel.Core.Models;

public sealed record MitreTechnique(string Id, string Tactic, string Name);

public sealed record MitreCoverageEntry(
    string TechniqueId,
    string TacticSlug,
    string Name,
    string EngineModule,
    string ContainmentAction);

public static class MitreAttackCatalog
{
    private static readonly MitreCoverageEntry[] CoveredTechniques =
    {
        new("T1003.001", "credential-access", "OS Credential Dumping: LSASS Memory", "ProcessRuleEvaluator + FilelessScriptGuard", "Process-Tree Freeze + Kill"),
        new("T1003.002", "credential-access", "OS Credential Dumping: SAM / SECURITY / SYSTEM", "ProcessRuleEvaluator", "Process-Tree Freeze + Kill"),
        new("T1003.003", "credential-access", "OS Credential Dumping: NTDS", "CustomRuleEngine (AEGIS-004)", "Process-Tree Freeze + Kill"),
        new("T1027", "defense-evasion", "Obfuscated Files or Information (PE Packer / Polymorphic Script)", "PeStaticAnalyzer + FilelessScriptGuard + ScriptFileAnalyzer", "Pre-Exec Quarantine / Freeze"),
        new("T1036.003", "defense-evasion", "Masquerading: Rename System Utilities (LOLBin OriginalFilename)", "ProcessRuleEvaluator", "Process-Tree Freeze + Kill"),
        new("T1036.005", "defense-evasion", "Masquerading: Match Legitimate Name or Location (Fake svchost/lsass)", "ProcessRuleEvaluator", "Process-Tree Freeze + Quarantine"),
        new("T1036.007", "defense-evasion", "Masquerading: Double File Extension (.pdf.exe / .hwp.lnk)", "ProcessRuleEvaluator + ThreatScanner + ZipArchiveAnalyzer", "Pre-Exec Quarantine / Freeze"),
        new("T1041", "exfiltration", "Exfiltration Over C2 Channel (HTTPS 443 / Credential Chain)", "NetworkGuardMonitor + BehaviorRiskEngine", "Process-Tree Freeze + WFP Firewall Block"),
        new("T1053.005", "persistence", "Scheduled Task/Job: Scheduled Task", "PersistenceMonitor + ProcessRuleEvaluator", "Task Inventory + Alert"),
        new("T1055", "defense-evasion", "Process Injection (Unbacked Private RWX / Reflective Load)", "MemoryInspectionGuard + FilelessScriptGuard", "Process-Tree Freeze"),
        new("T1055.012", "defense-evasion", "Process Hollowing / Process Ghosting", "MemoryInspectionGuard", "Process-Tree Freeze + Kill"),
        new("T1059.001", "execution", "Command and Scripting Interpreter: PowerShell (-EncodedCommand / 4104)", "ProcessRuleEvaluator + FilelessScriptGuard", "Base64 Decode + Freeze"),
        new("T1059.003", "execution", "Command and Scripting Interpreter: Windows Command Shell (Caret Obfuscation)", "ScriptFileAnalyzer + ProcessRuleEvaluator", "Pre-Exec Quarantine / Freeze"),
        new("T1059.005", "execution", "Command and Scripting Interpreter: Visual Basic / JScript COM Dropper", "ScriptFileAnalyzer + ZipArchiveAnalyzer", "Pre-Exec Quarantine"),
        new("T1071", "command-and-control", "Application Layer Protocol (ETW DNS + IPv4/IPv6 + Threat Intel IOC)", "EtwDnsTelemetryService + NetworkGuardMonitor + ThreatIntelStore", "Pre-Connect Freeze + WFP Block"),
        new("T1090", "command-and-control", "Proxy Hijacking (WinInet ProxyServer / PAC AutoConfigURL)", "EtwKernelTelemetryService + SystemIntegrityGuard", "1-Click Proxy & PAC Rollback"),
        new("T1091", "initial-access", "Replication Through Removable Media & MotW Downloads", "DownloadAndUsbGuard + ThreatScanner + ZipArchiveAnalyzer", "Instant Quarantine"),
        new("T1115", "collection", "Clipboard Data / ClickFix Social Engineering Payload", "ClipboardGuard (WM_CLIPBOARDUPDATE Hook)", "Real-Time Warning Alert"),
        new("T1127.001", "defense-evasion", "Trusted Developer Utilities Proxy Execution: MSBuild", "CustomRuleEngine (AEGIS-002)", "Process-Tree Freeze"),
        new("T1140", "defense-evasion", "Deobfuscate/Decode Files or Information (Certutil Decode)", "CustomRuleEngine (AEGIS-001)", "Process-Tree Freeze"),
        new("T1195.002", "initial-access", "Supply Chain Compromise (Multi-Hop Launcher/WebView Lineage)", "ProcessTreeTracker + ProcessRuleEvaluator", "Process-Tree Freeze + Hash Pinning"),
        new("T1203", "execution", "Exploitation for Client Execution (HWP / Office / PDF / CHM)", "ProcessRuleEvaluator + LnkAndContainerAnalyzer", "Process-Tree Freeze + Quarantine"),
        new("T1204.002", "execution", "User Execution: Malicious File (.LNK / .ISO / .VHD / .ZIP)", "LnkAndContainerAnalyzer + ZipArchiveAnalyzer", "In-Memory Inspection + Quarantine"),
        new("T1218.004", "defense-evasion", "System Binary Proxy Execution: InstallUtil / RegAsm / Regsvr32 / Mshta", "CustomRuleEngine (AEGIS-003) + ProcessRuleEvaluator", "Process-Tree Freeze"),
        new("T1482", "discovery", "Domain Trust Discovery (nltest / adfind)", "CustomRuleEngine (AEGIS-005)", "Process-Tree Freeze"),
        new("T1486", "impact", "Data Encrypted for Impact (Canary + Magic-Header Entropy + Velocity)", "RansomwareDetector + CanaryManager + EntropyAnalyzer + RecoveryVault", "Freeze + 1-Click Vault Restore"),
        new("T1490", "impact", "Inhibit System Recovery (vssadmin / wmic shadowcopy / wbadmin / bcdedit)", "ProcessRuleEvaluator + ScriptFileAnalyzer", "Instant Freeze + Kill"),
        new("T1539", "credential-access", "Steal Web Session Cookie (Chrome/Edge ABE Remote Debugging)", "ProcessRuleEvaluator", "Process-Tree Freeze"),
        new("T1546.003", "persistence", "Event Triggered Execution: WMI Event Subscription", "PersistenceMonitor", "Real-Time Alert + Audit"),
        new("T1546.012", "persistence", "Event Triggered Execution: Image File Execution Options (IFEO Debugger)", "EtwKernelTelemetryService + PersistenceMonitor", "1-Click Registry Rollback"),
        new("T1547.001", "persistence", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", "EtwKernelTelemetryService + PersistenceMonitor", "Dual Quarantine + Registry Rollback"),
        new("T1547.004", "persistence", "Boot or Logon Autostart Execution: Winlogon Helper (Shell / Userinit)", "EtwKernelTelemetryService + PersistenceMonitor", "Safe Default Value Rollback"),
        new("T1548.002", "privilege-escalation", "Abuse Elevation Control Mechanism: Bypass UAC (ms-settings / fodhelper)", "EtwKernelTelemetryService + SystemIntegrityGuard + ProcessRuleEvaluator", "Instant Auto-Rollback + Freeze"),
        new("T1552.004", "credential-access", "Unsecured Credentials: Private Keys / Cloud / Crypto Wallets", "CredentialAndDllGuard + EtwKernelTelemetryService", "Process-Tree Freeze + NTFS ACL Lock"),
        new("T1554", "persistence", "Compromise Host Software Binary (SHA-256 Pinning Mismatch)", "ProcessRuleEvaluator + SecurityOrchestrator", "Whitelist Override + Freeze"),
        new("T1555.003", "credential-access", "Credentials from Password Stores: Web Browsers (Chrome/Edge/Firefox/Whale)", "CredentialAndDllGuard + EtwKernelTelemetryService", "Process-Tree Freeze"),
        new("T1562.001", "defense-evasion", "Impair Defenses: Disable or Modify Tools (AMSI / Defender Exclusions / Self-Defense)", "FilelessScriptGuard + SystemIntegrityGuard + PolicyIntegritySigner", "HMAC Auto-Heal + Freeze"),
        new("T1562.004", "defense-evasion", "Impair Defenses: Disable or Modify System Firewall", "ProcessRuleEvaluator + CustomRuleEngine (AEGIS-006)", "Process-Tree Freeze"),
        new("T1565.001", "impact", "Data Manipulation: Stored Data Manipulation (HOSTS DNS Hijacking)", "SystemIntegrityGuard", "Integrity Alert"),
        new("T1574.001", "persistence", "Hijack Execution Flow: DLL Search Order Hijacking (Browser/Launcher Side-Load)", "CredentialAndDllGuard + EtwKernelTelemetryService", "Freeze + DLL Quarantine")
    };

    public static IReadOnlyList<MitreCoverageEntry> GetAllCoveredTechniques() => CoveredTechniques;

    public static string ResolveTacticById(string? techniqueId)
    {
        if (string.IsNullOrWhiteSpace(techniqueId)) return "Defense Evasion";
        var hit = CoveredTechniques.FirstOrDefault(t => t.TechniqueId.Equals(techniqueId, StringComparison.OrdinalIgnoreCase));
        return hit is not null ? hit.TacticSlug : "Execution / Defense Evasion";
    }

    /// <summary>
    /// Exports a valid MITRE ATT&amp;CK Navigator v4.5 Enterprise Layer JSON file that can be loaded directly
    /// into https://mitre-attack.github.io/attack-navigator/ to visualize AegisSentinel's full detection coverage
    /// and any actively observed threats on the host.
    /// </summary>
    public static string ExportNavigatorLayerJson(IReadOnlyList<SecurityEvent>? observedEvents = null)
    {
        var observedCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        if (observedEvents is not null)
        {
            foreach (var ev in observedEvents)
            {
                ev.EnsureMitrePopulated();
                if (!string.IsNullOrWhiteSpace(ev.MitreTechniqueId))
                {
                    observedCounts[ev.MitreTechniqueId] = observedCounts.GetValueOrDefault(ev.MitreTechniqueId) + 1;
                }
            }
        }

        var techniques = CoveredTechniques.Select(c =>
        {
            int hits = observedCounts.GetValueOrDefault(c.TechniqueId);
            return new
            {
                techniqueID = c.TechniqueId,
                tactic = c.TacticSlug,
                color = hits > 0 ? "#ef4444" : "#10b981",
                comment = hits > 0
                    ? $"[OBSERVED {hits}x] {c.EngineModule} -> {c.ContainmentAction}"
                    : $"[COVERED] {c.EngineModule} -> {c.ContainmentAction}",
                enabled = true,
                score = hits > 0 ? 100 : 75
            };
        }).ToList();

        var layer = new
        {
            name = "AegisSentinel Enterprise v7.0 — Detection Coverage Matrix",
            versions = new { attack = "16", navigator = "5.0.1", layer = "4.5" },
            domain = "enterprise-attack",
            description = $"Automated MITRE ATT&CK coverage export ({CoveredTechniques.Length} techniques across 11 tactics) generated by AegisSentinel EDR.",
            filters = new { platforms = new[] { "Windows" } },
            sorting = 0,
            layout = new { layout = "side", aggregateFunction = "average", showID = true, showName = true },
            hideDisabled = false,
            techniques,
            gradient = new
            {
                colors = new[] { "#10b981", "#f59e0b", "#ef4444" },
                minValue = 0,
                maxValue = 100
            },
            legendItems = new[]
            {
                new { label = "AegisSentinel Covered Detection + Containment", color = "#10b981" },
                new { label = "Actively Observed Threat on Endpoint", color = "#ef4444" }
            }
        };

        return JsonSerializer.Serialize(layer, new JsonSerializerOptions { WriteIndented = true });
    }

    public static MitreTechnique Resolve(ThreatCategory category, string? title = null)
    {
        var t = title ?? string.Empty;

        if (t.Contains("섀도", StringComparison.OrdinalIgnoreCase) || t.Contains("복구 삭제", StringComparison.OrdinalIgnoreCase))
        {
            return new("T1490", "Impact", "Inhibit System Recovery");
        }

        if (t.Contains("이중 확장자", StringComparison.OrdinalIgnoreCase))
        {
            return new("T1036.007", "Defense Evasion", "Double File Extension");
        }

        if (t.Contains("AMSI", StringComparison.OrdinalIgnoreCase) || t.Contains("Defender 무력화", StringComparison.OrdinalIgnoreCase))
        {
            return new("T1562.001", "Defense Evasion", "Disable or Modify Tools");
        }

        if (t.Contains("메모리 인젝션", StringComparison.OrdinalIgnoreCase) || t.Contains("RWX", StringComparison.OrdinalIgnoreCase))
        {
            return new("T1055", "Defense Evasion / Privilege Escalation", "Process Injection");
        }

        if (t.Contains("원격 디버깅", StringComparison.OrdinalIgnoreCase) || t.Contains("remote-debugging", StringComparison.OrdinalIgnoreCase))
        {
            return new("T1539", "Credential Access", "Steal Web Session Cookie (ABE Bypass)");
        }

        if (t.Contains("LSASS", StringComparison.OrdinalIgnoreCase) || t.Contains("SAM", StringComparison.OrdinalIgnoreCase))
        {
            return new("T1003.001", "Credential Access", "OS Credential Dumping (LSASS/SAM)");
        }

        if (t.Contains("프록시", StringComparison.OrdinalIgnoreCase) || t.Contains("PAC", StringComparison.OrdinalIgnoreCase))
        {
            return new("T1090", "Command and Control", "Proxy / PAC Hijacking");
        }

        return category switch
        {
            ThreatCategory.Masquerading => new("T1036.003", "Defense Evasion", "Masquerading: Rename / Fake System Binary"),
            ThreatCategory.SelfDefenseTamper => new("T1562.001", "Defense Evasion", "Impair Defenses: Security Policy Tampering"),
            ThreatCategory.ClipboardAttack => new("T1115", "Collection / Execution", "Clipboard Hijack / ClickFix"),
            ThreatCategory.SystemIntegrityTamper => new("T1565.001", "Impact / Defense Evasion", "Hosts / Proxy / Defender Exclusion Tampering"),
            ThreatCategory.DocumentExploit => new("T1203", "Execution", "Exploitation for Client Execution (HWP/Office/PDF/CHM)"),
            ThreatCategory.PrivilegeEscalation => new("T1548.002", "Privilege Escalation", "Bypass User Account Control / BYOVD / Admin Account"),
            ThreatCategory.SupplyChain => new("T1195.002", "Initial Access", "Compromise Software Supply Chain"),
            ThreatCategory.BinaryTampering => new("T1554", "Persistence", "Compromise Host Software Binary"),
            ThreatCategory.Ransomware => new("T1486", "Impact", "Data Encrypted for Impact"),
            ThreatCategory.DllHijacking => new("T1574.001", "Persistence / Defense Evasion", "DLL Search Order Hijacking"),
            ThreatCategory.CredentialAccess => t.Contains("브라우저", StringComparison.OrdinalIgnoreCase)
                ? new("T1555.003", "Credential Access", "Credentials from Web Browsers")
                : new("T1552.004", "Credential Access", "Private Keys & Cloud Credentials"),
            ThreatCategory.Persistence => t.Contains("작업 스케줄", StringComparison.OrdinalIgnoreCase)
                ? new("T1053.005", "Persistence", "Scheduled Task")
                : (t.Contains("WMI", StringComparison.OrdinalIgnoreCase)
                    ? new("T1546.003", "Persistence", "WMI Event Subscription")
                    : new("T1547.001", "Persistence", "Registry Run Keys / Startup Folder")),
            ThreatCategory.UnsignedExecution => new("T1204.002", "Execution", "Malicious File Execution"),
            ThreatCategory.NetworkAnomaly => new("T1071", "Command and Control", "Application Layer Protocol / C2"),
            ThreatCategory.Exfiltration => new("T1041", "Exfiltration", "Exfiltration Over C2 Channel"),
            ThreatCategory.FilelessScript => new("T1059.001", "Execution", "PowerShell / Fileless Script"),
            ThreatCategory.MemoryInjection => new("T1055.012", "Defense Evasion", "Unbacked Executable Memory / Injection"),
            ThreatCategory.UsbOrDownloadThreat => new("T1091", "Initial Access", "Removable Media / Internet Download"),
            ThreatCategory.StaticMalware => new("T1027", "Defense Evasion", "Packed / Obfuscated Malicious PE"),
            _ => new("T1562", "Defense Evasion", "System Security Configuration")
        };
    }
}
