using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using AegisSentinel.Core.Models;
using AegisSentinel.Core.Services;

namespace AegisSentinel.Core.Engine;

public sealed record PupSignatureRule
{
    public string Id { get; init; } = string.Empty;
    public string Name { get; init; } = string.Empty;
    public string Category { get; init; } = "PUP/Grid";
    public string Description { get; init; } = string.Empty;
    public string NameRegex { get; init; } = string.Empty;
    public bool Enabled { get; init; } = true;
}

/// <summary>
/// MZK-style deep browser profile (Preferences + Secure Preferences JSON, default search hijack,
/// sideloaded/MV3 high-risk Extensions manifest.json) and declarative Korean Grid Delivery / Adware (PUP)
/// scanner &amp; surgical cleaner with DPAPI+HMAC self-defense and ReDoS-immune NonBacktracking regexes.
/// </summary>
public sealed class BrowserAndPupCleaner
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private static readonly string[] KnownBrowserHijackerDomains =
    {
        "conduit.com", "mystartsearch.com", "trovi.com", "delta-homes.com", "sweet-page.com",
        "hao123.com", "2345.com", "omniboxes.com", "qone8.com", "babylon.com", "istartsurf.com",
        "v9.com", "oursearching.com", "searchprotect.com", "yoursites123.com", "luckysearches.com"
    };

    private static readonly string[] OfficialExtensionUpdateHosts =
    {
        "clients2.google.com", "edge.microsoft.com", "store.whale.naver.com", "go-updater.brave.com"
    };

    private readonly ThreatIntelStore _intelStore;
    private readonly PolicyIntegritySigner _signer;
    private readonly object _fileSync = new();
    private readonly string _pupDbPath;
    private volatile IReadOnlyList<(PupSignatureRule Rule, Regex Matcher)> _compiledPupRules =
        Array.Empty<(PupSignatureRule, Regex)>();

    public string PupRulesFilePath => _pupDbPath;
    public int ActivePupRuleCount => _compiledPupRules.Count;
    public bool LastLoadDetectedTampering { get; private set; }

    public BrowserAndPupCleaner(ThreatIntelStore intelStore, string? baseDirectory = null, PolicyIntegritySigner? sharedSigner = null)
    {
        _intelStore = intelStore;
        var root = baseDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AegisSentinel");
        Directory.CreateDirectory(root);
        _pupDbPath = Path.Combine(root, "pup_rules.json");
        _signer = sharedSigner ?? new PolicyIntegritySigner(root);
        LoadOrCreatePupRules();
    }

    public bool VerifyIntegrity(out string reason)
    {
        lock (_fileSync)
        {
            return _signer.VerifyFile(_pupDbPath, out reason);
        }
    }

    public void Reload() => LoadOrCreatePupRules();

    public IReadOnlyList<MalwareThreatItem> ScanBrowserProfiles(CancellationToken ct = default)
    {
        var findings = new List<MalwareThreatItem>();
        var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(localApp)) return findings;

        var browsers = new (string Name, string UserDataDir)[]
        {
            ("Chrome", Path.Combine(localApp, @"Google\Chrome\User Data")),
            ("Edge", Path.Combine(localApp, @"Microsoft\Edge\User Data")),
            ("Whale", Path.Combine(localApp, @"Naver\Naver Whale\User Data")),
            ("Brave", Path.Combine(localApp, @"BraveSoftware\Brave-Browser\User Data"))
        };

        foreach (var (browserName, userData) in browsers)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(userData)) continue;

            var profileDirs = new List<string>();
            var defaultProfile = Path.Combine(userData, "Default");
            if (Directory.Exists(defaultProfile)) profileDirs.Add(defaultProfile);
            try
            {
                foreach (var p in Directory.EnumerateDirectories(userData, "Profile *").Take(20))
                {
                    profileDirs.Add(p);
                }
            }
            catch { }

            foreach (var profile in profileDirs)
            {
                ct.ThrowIfCancellationRequested();

                // 1. Inspect BOTH Preferences and Secure Preferences JSON
                foreach (var prefName in new[] { "Preferences", "Secure Preferences" })
                {
                    var prefPath = Path.Combine(profile, prefName);
                    if (!File.Exists(prefPath)) continue;
                    try
                    {
                        var json = File.ReadAllText(prefPath);
                        findings.AddRange(AnalyzeBrowserPreferencesJson(json, prefPath, browserName, _intelStore));
                    }
                    catch { }
                }

                // 2. Inspect installed Extensions manifest.json (sorting version numbers numerically!)
                var extRoot = Path.Combine(profile, "Extensions");
                if (Directory.Exists(extRoot))
                {
                    try
                    {
                        foreach (var extIdDir in Directory.EnumerateDirectories(extRoot).Take(250))
                        {
                            ct.ThrowIfCancellationRequested();
                            var verDir = Directory.EnumerateDirectories(extIdDir)
                                .OrderByDescending(d => ParseVersionTuple(Path.GetFileName(d)))
                                .FirstOrDefault();
                            if (verDir is null) continue;
                            var manifestPath = Path.Combine(verDir, "manifest.json");
                            if (!File.Exists(manifestPath)) continue;

                            var manifestJson = File.ReadAllText(manifestPath);
                            var extThreat = AnalyzeExtensionManifest(manifestJson, extIdDir, browserName);
                            if (extThreat is not null)
                            {
                                findings.Add(extThreat);
                            }
                        }
                    }
                    catch { }
                }
            }
        }

        return findings;
    }

    public static IReadOnlyList<MalwareThreatItem> AnalyzeBrowserPreferencesJson(
        string json,
        string preferencesPath,
        string browserName,
        ThreatIntelStore? intelStore = null)
    {
        var results = new List<MalwareThreatItem>();
        if (string.IsNullOrWhiteSpace(json)) return results;

        try
        {
            var root = JsonNode.Parse(json) as JsonObject;
            if (root is null) return results;

            // 1. Check homepage
            if (TryReadString(root["homepage"], out var homepage) && IsHijackedUrl(homepage, intelStore))
            {
                results.Add(new MalwareThreatItem
                {
                    Stage = MalwareScanStage.BrowserHijack,
                    ThreatName = $"Hijacker.Browser.{browserName}Homepage",
                    CategoryLabel = "브라우저 홈페이지 변조",
                    Severity = ThreatSeverity.High,
                    RiskScore = 82,
                    TargetPath = preferencesPath,
                    EntryName = $"homepage::{homepage}",
                    SignatureLabel = $"{browserName} Preferences JSON",
                    Description = $"{browserName} 홈페이지가 알려진 하이재커/애드웨어 URL로 변조되어 있습니다: {homepage}",
                    ActionType = RemediationActionType.CleanBrowserPreferences,
                    RecommendedForCure = true
                });
            }

            // 2. Check session.startup_urls
            if (root["session"]?["startup_urls"] is JsonArray startupUrls)
            {
                foreach (var node in startupUrls)
                {
                    if (TryReadString(node, out var url) && IsHijackedUrl(url, intelStore))
                    {
                        results.Add(new MalwareThreatItem
                        {
                            Stage = MalwareScanStage.BrowserHijack,
                            ThreatName = $"Hijacker.Browser.{browserName}StartupUrl",
                            CategoryLabel = "브라우저 시작페이지 변조",
                            Severity = ThreatSeverity.High,
                            RiskScore = 82,
                            TargetPath = preferencesPath,
                            EntryName = $"startup_url::{url}",
                            SignatureLabel = $"{browserName} Preferences JSON",
                            Description = $"{browserName} 시작 페이지에 하이재커/애드웨어 URL이 주입되어 있습니다: {url}",
                            ActionType = RemediationActionType.CleanBrowserPreferences,
                            RecommendedForCure = true
                        });
                    }
                }
            }

            // 3. Check default_search_provider_data.template_url_data.url (classic MZK search hijacker target!)
            if (TryReadString(root["default_search_provider_data"]?["template_url_data"]?["url"], out var searchUrl) &&
                IsHijackedUrl(searchUrl, intelStore))
            {
                results.Add(new MalwareThreatItem
                {
                    Stage = MalwareScanStage.BrowserHijack,
                    ThreatName = $"Hijacker.Browser.{browserName}SearchEngine",
                    CategoryLabel = "브라우저 기본 검색엔진 변조",
                    Severity = ThreatSeverity.High,
                    RiskScore = 85,
                    TargetPath = preferencesPath,
                    EntryName = $"search_url::{searchUrl}",
                    SignatureLabel = $"{browserName} Preferences JSON",
                    Description = $"{browserName} 기본 검색 엔진이 하이재커 URL로 변조되어 있습니다: {searchUrl}",
                    ActionType = RemediationActionType.CleanBrowserPreferences,
                    RecommendedForCure = true
                });
            }
        }
        catch { }

        return results;
    }

    public static MalwareThreatItem? AnalyzeExtensionManifest(string manifestJson, string extensionDir, string browserName)
    {
        if (string.IsNullOrWhiteSpace(manifestJson)) return null;
        try
        {
            using var doc = JsonDocument.Parse(manifestJson);
            var root = doc.RootElement;

            var name = root.TryGetProperty("name", out var n) ? (n.GetString() ?? "Unknown Extension") : "Unknown Extension";
            var updateUrl = root.TryGetProperty("update_url", out var u) ? (u.GetString() ?? string.Empty).Trim() : string.Empty;

            // Strict HTTPS host equality check (prevents ?clients2.google.com or clients2.google.com.evil.com bypass!)
            if (!string.IsNullOrWhiteSpace(updateUrl) &&
                Uri.TryCreate(updateUrl, UriKind.Absolute, out var updateUri) &&
                updateUri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) &&
                OfficialExtensionUpdateHosts.Any(h => updateUri.Host.Equals(h, StringComparison.OrdinalIgnoreCase)))
            {
                return null;
            }

            // Require explicit non-official update_url (ignore local dev unpacked extensions unless they combine very high-risk perms)
            bool hasNonOfficialUpdateUrl = !string.IsNullOrWhiteSpace(updateUrl);
            var perms = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            CollectStringArray(root, "permissions", perms);
            CollectStringArray(root, "host_permissions", perms);

            bool hasBroadHost = perms.Contains("<all_urls>") || perms.Contains("*://*/*") || perms.Contains("http://*/*") || perms.Contains("https://*/*");
            bool hasSensitiveApi = perms.Contains("webRequestBlocking") || perms.Contains("cookies") ||
                                   perms.Contains("proxy") || perms.Contains("nativeMessaging") ||
                                   perms.Contains("debugger") || perms.Contains("declarativeNetRequest") ||
                                   perms.Contains("scripting");

            if (!hasBroadHost || !hasSensitiveApi) return null;
            if (!hasNonOfficialUpdateUrl && !perms.Contains("cookies") && !perms.Contains("nativeMessaging") && !perms.Contains("proxy"))
            {
                return null;
            }

            return new MalwareThreatItem
            {
                Stage = MalwareScanStage.BrowserHijack,
                ThreatName = $"Hijacker.Extension.{browserName}Sideload",
                CategoryLabel = "비공식 고위험 브라우저 확장",
                Severity = ThreatSeverity.High,
                RiskScore = 85,
                TargetPath = extensionDir,
                EntryName = name,
                SignatureLabel = $"{browserName} Extension Manifest",
                Description = hasNonOfficialUpdateUrl
                    ? $"비공식 업데이트 서버({updateUrl})를 사용하는 고권한 확장프로그램({name})이 감지되었습니다."
                    : $"스토어 출처 없는 사이드로드 고권한(쿠키/프록시/네이티브) 확장프로그램({name})이 감지되었습니다.",
                ActionType = RemediationActionType.RemoveBrowserExtension,
                RecommendedForCure = true
            };
        }
        catch
        {
            return null;
        }
    }

    public static (string CleanedJson, int RemovedCount) CleanBrowserPreferencesJson(string originalJson, IEnumerable<string> entryTokens)
    {
        var tokens = entryTokens.ToList();
        var root = JsonNode.Parse(originalJson) as JsonObject;
        if (root is null) return (originalJson, 0);

        int removed = 0;
        foreach (var token in tokens)
        {
            if (token.StartsWith("homepage::", StringComparison.OrdinalIgnoreCase))
            {
                var badUrl = token["homepage::".Length..];
                if (TryReadString(root["homepage"], out var current) &&
                    string.Equals(current, badUrl, StringComparison.OrdinalIgnoreCase))
                {
                    root["homepage"] = "about:blank";
                    root["homepage_is_newtabpage"] = true;
                    removed++;
                }
            }
            else if (token.StartsWith("startup_url::", StringComparison.OrdinalIgnoreCase))
            {
                var badUrl = token["startup_url::".Length..];
                if (root["session"]?["startup_urls"] is JsonArray arr)
                {
                    for (int i = arr.Count - 1; i >= 0; i--)
                    {
                        if (TryReadString(arr[i], out var val) &&
                            string.Equals(val, badUrl, StringComparison.OrdinalIgnoreCase))
                        {
                            arr.RemoveAt(i);
                            removed++;
                        }
                    }

                    if (arr.Count == 0 && root["session"] is JsonObject sessionObj)
                    {
                        sessionObj["restore_on_startup"] = 5; // Reset cleanly to New Tab Page
                    }
                }
            }
            else if (token.StartsWith("search_url::", StringComparison.OrdinalIgnoreCase))
            {
                var badUrl = token["search_url::".Length..];
                if (TryReadString(root["default_search_provider_data"]?["template_url_data"]?["url"], out var curSearch) &&
                    string.Equals(curSearch, badUrl, StringComparison.OrdinalIgnoreCase))
                {
                    root.Remove("default_search_provider_data");
                    removed++;
                }
            }
        }

        if (removed > 0)
        {
            // Clean corresponding Chromium Secure Preferences HMAC entries so Chrome/Edge smoothly recomputes MACs
            // instead of reverting our repair or showing a profile reset warning
            if (root["protection"] is JsonObject protObj)
            {
                if (protObj["macs"] is JsonObject macsObj)
                {
                    macsObj.Remove("homepage");
                    macsObj.Remove("homepage_is_newtabpage");
                    macsObj.Remove("default_search_provider_data");
                    if (macsObj["session"] is JsonObject sessMacObj)
                    {
                        sessMacObj.Remove("startup_urls");
                        sessMacObj.Remove("restore_on_startup");
                    }
                }
                protObj.Remove("super_mac");
            }
        }

        return (root.ToJsonString(new JsonSerializerOptions
        {
            WriteIndented = false,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        }), removed);
    }

    public IReadOnlyList<MalwareThreatItem> ScanInstalledPups(CancellationToken ct = default)
    {
        var findings = new List<MalwareThreatItem>();
        var rules = _compiledPupRules;
        if (rules.Count == 0) return findings;

        // 1. Scan Windows Uninstall registry keys (HKLM/HKCU 32 & 64-bit)
        var uninstallRoots = new (RegistryKey Hive, string HiveName, string SubKey)[]
        {
            (Registry.LocalMachine, "HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (Registry.LocalMachine, "HKLM", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (Registry.CurrentUser,  "HKCU", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
        };

        foreach (var (hive, hiveName, subKey) in uninstallRoots)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var root = hive.OpenSubKey(subKey);
                if (root is null) continue;
                foreach (var appKeyName in root.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using var appKey = root.OpenSubKey(appKeyName);
                        if (appKey is null) continue;
                        var displayName = appKey.GetValue("DisplayName")?.ToString() ?? appKeyName;
                        var publisher = appKey.GetValue("Publisher")?.ToString()?.Trim() ?? string.Empty;
                        var installLoc = appKey.GetValue("InstallLocation")?.ToString() ?? string.Empty;

                        if (publisher.Equals("Microsoft Corporation", StringComparison.OrdinalIgnoreCase)) continue;

                        var match = MatchPupRule(displayName, appKeyName, rules);
                        if (match is not null)
                        {
                            findings.Add(new MalwareThreatItem
                            {
                                Stage = MalwareScanStage.PersistenceAndService,
                                ThreatName = $"PUA.Korea.{match.Id}",
                                CategoryLabel = $"국내 애드웨어/그리드 ({match.Category})",
                                Severity = ThreatSeverity.High,
                                RiskScore = 78,
                                TargetPath = $@"{hiveName}\{subKey}\{appKeyName}",
                                EntryName = displayName,
                                AssociatedFilePath = !string.IsNullOrWhiteSpace(installLoc) ? installLoc : null,
                                SignatureLabel = "Aegis PUP/그리드 룰 DB",
                                Description = $"[{match.Name}] {match.Description} (설치 항목: {displayName})",
                                ActionType = RemediationActionType.ManualReview,
                                RecommendedForCure = false
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        // 2. Scan active Windows Services against svcName, DisplayName, and executable filename
        try
        {
            using var servicesRoot = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (servicesRoot is not null)
            {
                foreach (var svcName in servicesRoot.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    using var svcKey = servicesRoot.OpenSubKey(svcName);
                    if (svcKey is null) continue;
                    if (svcKey.GetValue("Start") is int st && st == 4) continue;

                    var displayName = svcKey.GetValue("DisplayName")?.ToString() ?? string.Empty;
                    var imgPath = svcKey.GetValue("ImagePath")?.ToString() ?? string.Empty;
                    var exe = PersistenceMonitor.ExtractExecutablePath(Environment.ExpandEnvironmentVariables(imgPath));
                    var exeName = Path.GetFileNameWithoutExtension(exe);

                    var match = MatchPupRule(svcName, displayName, rules) ?? MatchPupRule(exeName, exeName, rules);
                    if (match is null) continue;

                    var pupSvcAssoc = File.Exists(exe) && !QuarantineManager.IsProtectedSystemOrSelfPath(exe) ? exe : null;
                    string? pupSvcSha256 = null;
                    if (pupSvcAssoc is not null)
                    {
                        try
                        {
                            using var fs = new FileStream(pupSvcAssoc, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                            pupSvcSha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(fs));
                        }
                        catch { }
                    }

                    findings.Add(new MalwareThreatItem
                    {
                        Stage = MalwareScanStage.PersistenceAndService,
                        ThreatName = $"PUA.GridService.{match.Id}",
                        CategoryLabel = "그리드 딜리버리 서비스 (MZK 대상)",
                        Severity = ThreatSeverity.High,
                        RiskScore = 82,
                        TargetPath = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                        EntryName = svcName,
                        AssociatedFilePath = pupSvcAssoc,
                        AssociatedFileSha256 = pupSvcSha256,
                        SignatureLabel = "Aegis PUP/그리드 룰 DB",
                        Description = $"PC 리소스/네트워크를 몰래 점유하는 그리드 딜리버리 서비스 감지: {svcName} ({match.Description})",
                        ActionType = RemediationActionType.DisableMaliciousService,
                        RecommendedForCure = true
                    });
                }
            }
        }
        catch { }

        return findings;
    }

    public PupSignatureRule? MatchPupName(string candidate) => MatchPupRule(candidate, candidate, _compiledPupRules);

    private static PupSignatureRule? MatchPupRule(
        string nameA,
        string nameB,
        IReadOnlyList<(PupSignatureRule Rule, Regex Matcher)> rules)
    {
        if (string.IsNullOrWhiteSpace(nameA) && string.IsNullOrWhiteSpace(nameB)) return null;
        foreach (var (rule, regex) in rules)
        {
            if (!rule.Enabled) continue;
            try
            {
                if ((!string.IsNullOrWhiteSpace(nameA) && regex.IsMatch(nameA)) ||
                    (!string.IsNullOrWhiteSpace(nameB) && regex.IsMatch(nameB)))
                {
                    return rule;
                }
            }
            catch (RegexMatchTimeoutException) { }
        }
        return null;
    }

    private static bool TryReadString(JsonNode? node, out string value)
    {
        if (node is JsonValue jv && jv.TryGetValue<string>(out var s) && !string.IsNullOrWhiteSpace(s))
        {
            value = s;
            return true;
        }
        value = string.Empty;
        return false;
    }

    private static (int, int, int, int) ParseVersionTuple(string? versionText)
    {
        if (string.IsNullOrWhiteSpace(versionText)) return (0, 0, 0, 0);
        var parts = versionText.Split(new[] { '.', '_' }, StringSplitOptions.RemoveEmptyEntries);
        int p0 = parts.Length > 0 && int.TryParse(parts[0], out var v0) ? v0 : 0;
        int p1 = parts.Length > 1 && int.TryParse(parts[1], out var v1) ? v1 : 0;
        int p2 = parts.Length > 2 && int.TryParse(parts[2], out var v2) ? v2 : 0;
        int p3 = parts.Length > 3 && int.TryParse(parts[3], out var v3) ? v3 : 0;
        return (p0, p1, p2, p3);
    }

    public static bool IsHijackedUrl(string url, ThreatIntelStore? intelStore)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return false;
        var host = uri.Host;
        if (string.IsNullOrWhiteSpace(host)) return false;

        if (KnownBrowserHijackerDomains.Any(h => host.Equals(h, StringComparison.OrdinalIgnoreCase) ||
                                                 host.EndsWith("." + h, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        return intelStore is not null && intelStore.IsAdwareOrMalwareDomain(host);
    }

    private static void CollectStringArray(JsonElement root, string propName, HashSet<string> target)
    {
        if (!root.TryGetProperty(propName, out var arr) || arr.ValueKind != JsonValueKind.Array) return;
        foreach (var item in arr.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.String)
            {
                var v = item.GetString();
                if (!string.IsNullOrWhiteSpace(v)) target.Add(v);
            }
        }
    }

    public static List<PupSignatureRule> CreateDefaultPupRules() => new()
    {
        new PupSignatureRule
        {
            Id = "PUP-KR-001",
            Name = "NATService / Grid Delivery Agent",
            Category = "GridDelivery",
            Description = "웹하드·다운로더 설치 시 동반 설치되어 백그라운드 업로드를 점유하는 NATService 계열 그리드 에이전트",
            NameRegex = @"\b(nat[\s_-]?service|natsvc|k?grid[\s_-]?service)\b"
        },
        new PupSignatureRule
        {
            Id = "PUP-KR-002",
            Name = "MicroCloudEngine / WinCloud Grid",
            Category = "GridDelivery",
            Description = "P2P 전송 대역폭을 백그라운드에서 점유하는 클라우드 그리드 딜리버리 에이전트",
            NameRegex = @"(microcloudengine|wincloudgrid|smartgridagent|cloudgridsvc)"
        },
        new PupSignatureRule
        {
            Id = "PUP-KR-003",
            Name = "Adware Popup / Coupon / Search Helper",
            Category = "Adware",
            Description = "브라우저 쇼핑 광고 팝업 및 검색 결과 가로채기를 유발하는 국내 제휴 애드웨어(PUP)",
            NameRegex = @"(adpopuphelper|couponpopup|shoppingtabad|windowsearchhelper|smartbaradware|keywordmatchad)"
        },
        new PupSignatureRule
        {
            Id = "PUP-KR-004",
            Name = "Fake System Optimizer / Scareware",
            Category = "Scareware",
            Description = "가짜 오류를 띄워 결제를 유도하거나 광고를 삽입하는 불필요한 최적화 유틸리티",
            NameRegex = @"(pcboostpro_ad|driverfixscam|cleanmaster_pup|speedupmypc_ad)"
        }
    };

    private void LoadOrCreatePupRules()
    {
        lock (_fileSync)
        {
            LastLoadDetectedTampering = false;
            try
            {
                List<PupSignatureRule>? rules = null;
                if (File.Exists(_pupDbPath))
                {
                    if (!_signer.VerifyFile(_pupDbPath, out _))
                    {
                        LastLoadDetectedTampering = true;
                    }
                    else
                    {
                        rules = JsonSerializer.Deserialize<List<PupSignatureRule>>(File.ReadAllText(_pupDbPath));
                        if (rules is { Count: > 0 } && !File.Exists(_pupDbPath + ".hmac"))
                        {
                            _signer.SignFile(_pupDbPath);
                        }
                    }
                }

                if (rules is null || rules.Count == 0)
                {
                    rules = CreateDefaultPupRules();
                    try
                    {
                        if (File.Exists(_pupDbPath)) File.SetAttributes(_pupDbPath, FileAttributes.Normal);
                        File.WriteAllText(_pupDbPath, JsonSerializer.Serialize(rules, JsonOptions), Encoding.UTF8);
                        _signer.SignFile(_pupDbPath);
                    }
                    catch { }
                }

                var compiled = new List<(PupSignatureRule, Regex)>();
                foreach (var r in rules.Where(x => x.Enabled && !string.IsNullOrWhiteSpace(x.NameRegex)))
                {
                    try
                    {
                        compiled.Add((r, new Regex(r.NameRegex, RegexOptions.IgnoreCase | RegexOptions.NonBacktracking, TimeSpan.FromMilliseconds(200))));
                    }
                    catch { }
                }
                _compiledPupRules = compiled;
            }
            catch { }
        }
    }
}
