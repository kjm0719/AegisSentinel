using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using AegisSentinel.Core.Models;

namespace AegisSentinel.Core.Services;

public sealed record CloudReputationResult(
    bool Checked,
    bool IsMalicious,
    int MaliciousDetections,
    int TotalEngines,
    string Summary);

public sealed record ThreatFeedSyncResult(
    bool Success,
    int AddedIps,
    int AddedDomains,
    int TotalIps,
    int TotalDomains,
    string Summary);

/// <summary>
/// Manages local IOC blocklists (SHA-256 hashes, C2 IPs, malicious domains),
/// syncs live public Abuse.ch threat intelligence feeds (Feodo Tracker C2 IPs + URLhaus domains),
/// and provides optional privacy-preserving hash-only reputation lookup via VirusTotal v3.
/// </summary>
public sealed class ThreatIntelStore
{
    private const string FeodoIpBlocklistUrl = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt";
    private const string IpsumIpBlocklistUrl = "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt";
    private const string UrlhausOnlineFilterUrl = "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains-online.txt";
    private const string StevenBlackAdwareMalwareUrl = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts";

    // Never allow a public feed to accidentally block core OS/cloud/CDN/dev/Korean everyday platforms or their subdomains
    private static readonly HashSet<string> ProtectedMajorDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "google.com", "googleapis.com", "gstatic.com", "youtube.com",
        "microsoft.com", "windows.com", "windowsupdate.com", "windows.net", "live.com", "office.com", "office365.com",
        "exp-tas.com", "msftncsi.com", "msftconnecttest.com", "msn.com", "bing.com", "azure.com", "azureedge.net",
        "trafficmanager.net", "visualstudio.com", "vscode-cdn.net",
        "digicert.com", "sectigo.com", "globalsign.com", "letsencrypt.org",
        "github.com", "githubusercontent.com", "cloudflare.com", "amazonaws.com", "cloudfront.net",
        "fastly.net", "akamaihd.net", "akamaiedge.net", "vercel.app", "netlify.app", "imgix.net",
        "nuget.org", "npmjs.org", "pypi.org", "python.org",
        "mozilla.org", "firefox.com", "brave.com", "discord.com", "discordapp.com", "steampowered.com",
        "naver.com", "kakao.com", "daum.net", "coupang.com", "apple.com"
    };

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private static readonly HttpClient SharedHttp = new() { Timeout = TimeSpan.FromSeconds(45) };

    private readonly object _sync = new();
    private HashSet<string> _hashes = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _ips = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _domains = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _feedIps = new(StringComparer.OrdinalIgnoreCase);
    // Strict separation:
    // _c2FeedDomains = confirmed malware C2 domains (URLhaus) -> used for real-time ETW DNS Critical alerts & process freeze
    // _adwareFeedDomains = StevenBlack adware/telemetry/hijacker hosts -> used for browser hijack & PUP cleaning ONLY (never freezes OS apps!)
    private HashSet<string> _c2FeedDomains = new(StringComparer.OrdinalIgnoreCase);
    private HashSet<string> _adwareFeedDomains = new(StringComparer.OrdinalIgnoreCase);
    private DateTimeOffset? _lastFeedSyncUtc;
    private int _isSyncingFullDb;

    public string IntelFilePath { get; }
    public string FeedDomainsFilePath { get; }
    public MalwareHashDatabase HashDb { get; }
    public bool HasBlockedHashes { get { lock (_sync) return _hashes.Count > 0 || HashDb.HashCount > 0; } }
    public int TotalBlockedHashCount { get { lock (_sync) return _hashes.Count + HashDb.HashCount; } }
    public int TotalBlockedIpCount { get { lock (_sync) return _ips.Count + _feedIps.Count; } }
    public int TotalBlockedDomainCount { get { lock (_sync) return _domains.Count + _c2FeedDomains.Count + _adwareFeedDomains.Count; } }
    public DateTimeOffset? LastFeedSyncUtc { get { lock (_sync) return _lastFeedSyncUtc; } }
    public bool IsFeedSyncDue { get { lock (_sync) return !_lastFeedSyncUtc.HasValue || (DateTimeOffset.UtcNow - _lastFeedSyncUtc.Value).TotalHours >= 24; } }
    public bool IsFullDatabaseSyncDue
    {
        get
        {
            if (IsFeedSyncDue) return true;
            if (HashDb.HashCount == 0 || !HashDb.LastUpdatedUtc.HasValue) return true;
            return (DateTimeOffset.UtcNow - HashDb.LastUpdatedUtc.Value).TotalHours >= 24;
        }
    }

    public ThreatIntelStore(string? baseDirectory = null)
    {
        var root = baseDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AegisSentinel");
        Directory.CreateDirectory(root);
        IntelFilePath = Path.Combine(root, "intel.json");
        FeedDomainsFilePath = Path.Combine(root, "feed_domains.txt");
        HashDb = new MalwareHashDatabase(root);
        Load();
    }

    public bool IsUserHashBlocked(string? sha256)
    {
        if (string.IsNullOrWhiteSpace(sha256)) return false;
        var clean = sha256.Trim();
        lock (_sync)
        {
            return _hashes.Count > 0 && _hashes.Contains(clean);
        }
    }

    public bool IsHashBlocked(string? sha256)
    {
        if (string.IsNullOrWhiteSpace(sha256)) return false;
        var clean = sha256.Trim();
        lock (_sync)
        {
            if (_hashes.Count > 0 && _hashes.Contains(clean)) return true;
        }
        return HashDb.ContainsHexSha256(clean);
    }

    public bool IsUserIpBlocked(string? ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return false;
        var clean = ip.Trim();
        lock (_sync) return _ips.Contains(clean);
    }

    public bool IsPublicFeedIpBlocked(string? ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return false;
        var clean = ip.Trim();
        if (IPAddress.TryParse(clean, out var parsed) && IsProtectedInfrastructureOrCdnIp(parsed)) return false;
        lock (_sync) return _feedIps.Contains(clean);
    }

    public bool IsIpBlocked(string? ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return false;
        var clean = ip.Trim();
        lock (_sync)
        {
            if (_ips.Contains(clean)) return true;
            if (!_feedIps.Contains(clean)) return false;
        }
        return !IPAddress.TryParse(clean, out var parsed) || !IsProtectedInfrastructureOrCdnIp(parsed);
    }

    public static bool IsProtectedDomain(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return false;
        return IsProtectedMajorDomainOrSubdomain(domain.Trim().TrimEnd('.'));
    }

    /// <summary>
    /// O(labels) zero-linear-scan suffix lookup for CONFIRMED MALWARE / C2 domains ONLY (user IOC + URLhaus).
    /// Excludes ad/telemetry hosts (StevenBlack) and ProtectedMajorDomains (e.g. Microsoft exp-tas.com)
    /// so real-time ETW DNS alerting &amp; process freeze NEVER false-trigger on OS telemetry or ads!
    /// </summary>
    public bool IsDomainBlocked(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return false;
        var d = domain.Trim().TrimEnd('.');
        if (d.Length == 0 || IsProtectedMajorDomainOrSubdomain(d)) return false;

        lock (_sync)
        {
            if (_domains.Count == 0 && _c2FeedDomains.Count == 0) return false;
            return MatchesDomainSetLocked(d, _domains, _c2FeedDomains);
        }
    }

    /// <summary>
    /// Broader lookup including StevenBlack adware/hijacker hosts — used for Browser Homepage/Search hijack cleaning.
    /// </summary>
    public bool IsAdwareOrMalwareDomain(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return false;
        var d = domain.Trim().TrimEnd('.');
        if (d.Length == 0 || IsProtectedMajorDomainOrSubdomain(d)) return false;

        lock (_sync)
        {
            if (_domains.Count == 0 && _c2FeedDomains.Count == 0 && _adwareFeedDomains.Count == 0) return false;
            return MatchesDomainSetLocked(d, _domains, _c2FeedDomains) ||
                   MatchesSingleSetLocked(d, _adwareFeedDomains);
        }
    }

    private static bool MatchesDomainSetLocked(string d, HashSet<string> primary, HashSet<string> secondary)
    {
        if (primary.Contains(d) || secondary.Contains(d)) return true;

        int dotIdx = d.IndexOf('.');
        while (dotIdx >= 0 && dotIdx < d.Length - 1)
        {
            var parent = d[(dotIdx + 1)..];
            if (primary.Contains(parent) || secondary.Contains(parent)) return true;
            dotIdx = d.IndexOf('.', dotIdx + 1);
        }
        return false;
    }

    private static bool MatchesSingleSetLocked(string d, HashSet<string> set)
    {
        if (set.Count == 0) return false;
        if (set.Contains(d)) return true;

        int dotIdx = d.IndexOf('.');
        while (dotIdx >= 0 && dotIdx < d.Length - 1)
        {
            if (set.Contains(d[(dotIdx + 1)..])) return true;
            dotIdx = d.IndexOf('.', dotIdx + 1);
        }
        return false;
    }

    public ThreatIntelDatabase GetSnapshot()
    {
        lock (_sync)
        {
            return new ThreatIntelDatabase(
                _hashes.OrderBy(x => x).ToList(),
                _ips.OrderBy(x => x).ToList(),
                _domains.OrderBy(x => x).ToList(),
                _lastFeedSyncUtc,
                _feedIps.OrderBy(x => x).ToList(),
                _c2FeedDomains.OrderBy(x => x).ToList());
        }
    }

    public void UpdateDatabase(IEnumerable<string> hashes, IEnumerable<string> ips, IEnumerable<string> domains)
    {
        lock (_sync)
        {
            _hashes = new HashSet<string>(hashes.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()), StringComparer.OrdinalIgnoreCase);
            _ips = new HashSet<string>(ips.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()), StringComparer.OrdinalIgnoreCase);
            _domains = new HashSet<string>(domains.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim().TrimEnd('.')), StringComparer.OrdinalIgnoreCase);
            SaveLocked();
        }
    }

    public void AddBlockedHash(string sha256)
    {
        if (string.IsNullOrWhiteSpace(sha256)) return;
        lock (_sync)
        {
            if (_hashes.Add(sha256.Trim()))
            {
                SaveLocked();
            }
        }
    }

    public void AddBlockedDomain(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return;
        lock (_sync)
        {
            if (_domains.Add(domain.Trim().TrimEnd('.')))
            {
                SaveLocked();
            }
        }
    }

    /// <summary>
    /// Downloads and merges verified open-source threat intelligence feeds (Abuse.ch Feodo Tracker C2 IPs
    /// and Abuse.ch URLhaus active malware domains) without erasing user-configured IOC entries.
    /// </summary>
    public async Task<ThreatFeedSyncResult> SyncPublicThreatFeedsAsync(CancellationToken ct = default)
    {
        int addedIps = 0;
        int addedDomains = 0;
        bool anySucceeded = false;
        var errors = new List<string>();
        var collectedIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var collectedC2Domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var collectedAdwareDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        bool feodoOk = false;
        bool ipsumOk = false;
        bool urlhausOk = false;
        bool stevenBlackOk = false;

        // 1. Abuse.ch Feodo Tracker (Botnet / Ransomware C2 IPs)
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, FeodoIpBlocklistUrl);
            req.Headers.UserAgent.ParseAdd("AegisSentinel/7.0");
            using var resp = await SharedHttp.SendAsync(req, ct);
            if (resp.IsSuccessStatusCode)
            {
                var body = await resp.Content.ReadAsStringAsync(ct);
                foreach (var ip in ParseFeodoIpList(body, maxCount: 5000)) collectedIps.Add(ip);
                feodoOk = true;
                anySucceeded = true;
            }
            else
            {
                errors.Add($"Feodo HTTP {(int)resp.StatusCode}");
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            errors.Add($"Feodo: {ex.Message}");
        }

        // 2. IPsum Level 3+ (Multi-blacklist confirmed malicious IPs)
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, IpsumIpBlocklistUrl);
            req.Headers.UserAgent.ParseAdd("AegisSentinel/7.0");
            using var resp = await SharedHttp.SendAsync(req, ct);
            if (resp.IsSuccessStatusCode)
            {
                var body = await resp.Content.ReadAsStringAsync(ct);
                foreach (var ip in ParseFeodoIpList(body, maxCount: 25_000)) collectedIps.Add(ip);
                ipsumOk = true;
                anySucceeded = true;
            }
            else
            {
                errors.Add($"IPsum HTTP {(int)resp.StatusCode}");
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            errors.Add($"IPsum: {ex.Message}");
        }

        // 3. URLhaus Online Malware Domains & Hosts (Abuse.ch mirror, updated hourly)
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, UrlhausOnlineFilterUrl);
            req.Headers.UserAgent.ParseAdd("AegisSentinel/7.0");
            using var resp = await SharedHttp.SendAsync(req, ct);
            if (resp.IsSuccessStatusCode)
            {
                var body = await resp.Content.ReadAsStringAsync(ct);
                foreach (var ip in ParseFeodoIpList(body, maxCount: 2000)) collectedIps.Add(ip);
                foreach (var dom in ParseUrlhausHostfile(body, maxCount: 20_000)) collectedC2Domains.Add(dom);
                urlhausOk = true;
                anySucceeded = true;
            }
            else
            {
                errors.Add($"URLhaus HTTP {(int)resp.StatusCode}");
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            errors.Add($"URLhaus: {ex.Message}");
        }

        // 4. StevenBlack Unified Adware + Malware Hosts (full ~140k+ adware/hijacker/malware domains)
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, StevenBlackAdwareMalwareUrl);
            req.Headers.UserAgent.ParseAdd("AegisSentinel/7.0");
            using var resp = await SharedHttp.SendAsync(req, ct);
            if (resp.IsSuccessStatusCode)
            {
                var body = await resp.Content.ReadAsStringAsync(ct);
                foreach (var dom in ParseUrlhausHostfile(body, maxCount: 250_000)) collectedAdwareDomains.Add(dom);
                stevenBlackOk = true;
                anySucceeded = true;
            }
            else
            {
                errors.Add($"StevenBlack HTTP {(int)resp.StatusCode}");
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            errors.Add($"StevenBlack: {ex.Message}");
        }

        int totalIps;
        int totalDomains;
        List<string>? domainsToPersist = null;
        ThreatIntelDatabase? dbToPersist = null;

        lock (_sync)
        {
            if (anySucceeded)
            {
                if (collectedIps.Count > 0)
                {
                    if ((!feodoOk || !ipsumOk) && _feedIps.Count > 0)
                    {
                        foreach (var oldIp in _feedIps) collectedIps.Add(oldIp);
                    }
                    addedIps = collectedIps.Count(ip => !_feedIps.Contains(ip));
                    _feedIps = collectedIps;
                }
                if (collectedC2Domains.Count > 0)
                {
                    if (!urlhausOk && _c2FeedDomains.Count > 0)
                    {
                        foreach (var oldDom in _c2FeedDomains) collectedC2Domains.Add(oldDom);
                    }
                    addedDomains += collectedC2Domains.Count(dom => !_c2FeedDomains.Contains(dom));
                    _c2FeedDomains = collectedC2Domains;
                }
                if (collectedAdwareDomains.Count > 0)
                {
                    if (!stevenBlackOk && _adwareFeedDomains.Count > 0)
                    {
                        foreach (var oldDom in _adwareFeedDomains) collectedAdwareDomains.Add(oldDom);
                    }
                    addedDomains += collectedAdwareDomains.Count(dom => !_adwareFeedDomains.Contains(dom));
                    _adwareFeedDomains = collectedAdwareDomains;
                }
                if ((feodoOk || ipsumOk) && (urlhausOk || stevenBlackOk))
                {
                    _lastFeedSyncUtc = DateTimeOffset.UtcNow;
                }
                dbToPersist = BuildIntelDbSnapshotLocked();
                domainsToPersist = _adwareFeedDomains.ToList();
            }
            totalIps = _ips.Count + _feedIps.Count;
            totalDomains = _domains.Count + _c2FeedDomains.Count + _adwareFeedDomains.Count;
        }

        if (dbToPersist is not null) WriteIntelAtomic(dbToPersist);
        if (domainsToPersist is not null) WriteFeedDomainsAtomic(domainsToPersist);

        var summary = anySucceeded
            ? $"글로벌 위협 피드(Feodo·IPsum·URLhaus·StevenBlack) 동기화 완료 — 신규 IP +{addedIps:N0} / 도메인 +{addedDomains:N0} (총 C2 IP {totalIps:N0}개, 악성·애드웨어 도메인 {totalDomains:N0}개)"
            : $"위협 피드 동기화 실패 (오프라인 또는 차단됨): {string.Join(" | ", errors)}";

        return new ThreatFeedSyncResult(anySucceeded, addedIps, addedDomains, totalIps, totalDomains, summary);
    }

    public async Task<(MalwareDbSyncResult HashResult, ThreatFeedSyncResult FeedResult)> SyncFullAntivirusDatabaseAsync(
        string? abuseChAuthKey = null,
        IProgress<string>? progress = null,
        CancellationToken ct = default)
    {
        if (Interlocked.Exchange(ref _isSyncingFullDb, 1) == 1)
        {
            return (
                new MalwareDbSyncResult(false, HashDb.HashCount, HashDb.DatabaseSizeBytes, "이미 바이러스 DB 업데이트가 진행 중입니다."),
                new ThreatFeedSyncResult(false, 0, 0, TotalBlockedIpCount, TotalBlockedDomainCount, "이미 위협 피드 동기화가 진행 중입니다."));
        }

        try
        {
            var hashRes = await HashDb.SyncPublicMalwareDatabaseAsync(abuseChAuthKey, progress, ct);
            progress?.Report("글로벌 애드웨어·멀웨어 도메인 및 C2 IP 피드 동기화 중...");
            var feedRes = await SyncPublicThreatFeedsAsync(ct);
            return (hashRes, feedRes);
        }
        finally
        {
            Interlocked.Exchange(ref _isSyncingFullDb, 0);
        }
    }

    public static IReadOnlyList<string> ParseFeodoIpList(string content, int maxCount = 2000)
    {
        var list = new List<string>();
        if (string.IsNullOrWhiteSpace(content)) return list;

        foreach (var raw in content.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
        {
            if (list.Count >= maxCount) break;
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith('!')) continue;

            var tokens = line.Split(new[] { ' ', '\t', ',' }, StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length == 0) continue;
            var firstToken = tokens[0].Trim();
            if (IPAddress.TryParse(firstToken, out var ip) &&
                !Engine.NetworkGuardMonitor.IsLocalOrPrivateIp(ip) &&
                !IsProtectedInfrastructureOrCdnIp(ip))
            {
                list.Add(ip.ToString());
            }
        }

        return list;
    }

    public static IReadOnlyList<string> ParseUrlhausHostfile(string content, int maxCount = 2500)
    {
        var list = new List<string>();
        if (string.IsNullOrWhiteSpace(content)) return list;

        foreach (var raw in content.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
        {
            if (list.Count >= maxCount) break;
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith('!')) continue;

            int commentIdx = line.IndexOf('#');
            if (commentIdx >= 0)
            {
                line = line[..commentIdx].Trim();
                if (line.Length == 0) continue;
            }

            var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0) continue;
            var candidate = parts.Length >= 2 && IPAddress.TryParse(parts[0], out _)
                ? parts[1].Trim().TrimEnd('.')
                : parts[0].Trim().TrimEnd('.');
            if (candidate.Length < 4 || candidate.Length > 253 || !candidate.Contains('.')) continue;
            if (candidate.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
                candidate.Equals("localhost.localdomain", StringComparison.OrdinalIgnoreCase)) continue;
            if (IPAddress.TryParse(candidate, out _)) continue;
            if (IsProtectedMajorDomainOrSubdomain(candidate)) continue;

            if (candidate.All(c => char.IsLetterOrDigit(c) || c is '.' or '-' or '_'))
            {
                list.Add(candidate.ToLowerInvariant());
            }
        }

        return list;
    }

    private static bool IsProtectedMajorDomainOrSubdomain(string domain)
    {
        if (ProtectedMajorDomains.Contains(domain)) return true;
        int dot = domain.IndexOf('.');
        while (dot >= 0 && dot < domain.Length - 1)
        {
            if (ProtectedMajorDomains.Contains(domain[(dot + 1)..])) return true;
            dot = domain.IndexOf('.', dot + 1);
        }
        return false;
    }

    /// <summary>
    /// Prevents noisy public IP feeds (e.g. IPsum) from blacklisting shared Anycast CDN, public DNS,
    /// or major cloud front-door ranges (Cloudflare, Fastly, Akamai, Microsoft FrontDoor/Azure/M365, Google, GitHub, CloudFront),
    /// which would otherwise falsely freeze browsers and OS apps on ordinary HTTPS traffic.
    /// </summary>
    public static bool IsProtectedInfrastructureOrCdnIp(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false;

        var b = ip.GetAddressBytes();
        uint v = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];

        static bool InCidr(uint addr, byte a, byte b1, byte c, byte d, int prefix)
        {
            uint net = ((uint)a << 24) | ((uint)b1 << 16) | ((uint)c << 8) | d;
            uint mask = prefix == 0 ? 0 : uint.MaxValue << (32 - prefix);
            return (addr & mask) == (net & mask);
        }

        // Public DNS resolvers (Cloudflare 1.1.1.0/24, 1.0.0.0/24; Google 8.8.8.0/24, 8.8.4.0/24; Quad9 9.9.9.0/24; OpenDNS)
        if (InCidr(v, 1, 1, 1, 0, 24) || InCidr(v, 1, 0, 0, 0, 24) ||
            InCidr(v, 8, 8, 8, 0, 24) || InCidr(v, 8, 8, 4, 0, 24) ||
            InCidr(v, 9, 9, 9, 0, 24) || InCidr(v, 208, 67, 222, 0, 23))
        {
            return true;
        }

        // Cloudflare Anycast CDN
        if (InCidr(v, 104, 16, 0, 0, 12) || InCidr(v, 172, 64, 0, 0, 13) ||
            InCidr(v, 162, 158, 0, 0, 15) || InCidr(v, 198, 41, 128, 0, 17) ||
            InCidr(v, 103, 21, 244, 0, 22) || InCidr(v, 103, 22, 200, 0, 22) ||
            InCidr(v, 103, 31, 4, 0, 22) || InCidr(v, 141, 101, 64, 0, 18) ||
            InCidr(v, 108, 162, 192, 0, 18) || InCidr(v, 190, 93, 240, 0, 20) ||
            InCidr(v, 188, 114, 96, 0, 20) || InCidr(v, 197, 234, 240, 0, 22))
        {
            return true;
        }

        // Fastly & GitHub Anycast
        if (InCidr(v, 151, 101, 0, 0, 16) || InCidr(v, 199, 232, 0, 0, 16) ||
            InCidr(v, 185, 199, 108, 0, 22) || InCidr(v, 140, 82, 112, 0, 20))
        {
            return true;
        }

        // Akamai Edge & CloudFront Anycast
        if (InCidr(v, 23, 0, 0, 0, 12) || InCidr(v, 23, 32, 0, 0, 11) || InCidr(v, 23, 64, 0, 0, 14) ||
            InCidr(v, 23, 192, 0, 0, 11) || InCidr(v, 104, 64, 0, 0, 10) ||
            InCidr(v, 13, 32, 0, 0, 15) || InCidr(v, 13, 224, 0, 0, 14) ||
            InCidr(v, 52, 84, 0, 0, 15) || InCidr(v, 99, 84, 0, 0, 16) ||
            InCidr(v, 143, 204, 0, 0, 16) || InCidr(v, 54, 230, 0, 0, 16))
        {
            return true;
        }

        // Microsoft Azure FrontDoor / M365 / Windows Update & Google Front-End
        if (InCidr(v, 13, 104, 0, 0, 14) || InCidr(v, 20, 0, 0, 0, 8) ||
            InCidr(v, 40, 64, 0, 0, 10) || InCidr(v, 52, 96, 0, 0, 12) ||
            InCidr(v, 142, 250, 0, 0, 15) || InCidr(v, 172, 217, 0, 0, 16))
        {
            return true;
        }

        return false;
    }

    /// <summary>
    /// Privacy-preserving hash-only lookup (never uploads file contents).
    /// Requires a user-supplied VirusTotal API key.
    /// </summary>
    public static async Task<CloudReputationResult> QueryVirusTotalHashAsync(string sha256, string apiKey)
    {
        if (string.IsNullOrWhiteSpace(apiKey) || string.IsNullOrWhiteSpace(sha256))
        {
            return new CloudReputationResult(false, false, 0, 0, "VirusTotal API 키 미설정");
        }

        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/files/{sha256.Trim()}");
            req.Headers.Add("x-apikey", apiKey.Trim());
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            using var resp = await SharedHttp.SendAsync(req);
            if ((int)resp.StatusCode == 404)
            {
                return new CloudReputationResult(true, false, 0, 0, "VirusTotal 미등록 해시");
            }

            if (!resp.IsSuccessStatusCode)
            {
                return new CloudReputationResult(false, false, 0, 0, $"조회 오류 (HTTP {(int)resp.StatusCode})");
            }

            var json = await resp.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);
            var stats = doc.RootElement.GetProperty("data").GetProperty("attributes").GetProperty("last_analysis_stats");
            int malicious = stats.TryGetProperty("malicious", out var m) ? m.GetInt32() : 0;
            int suspicious = stats.TryGetProperty("suspicious", out var s) ? s.GetInt32() : 0;
            int harmless = stats.TryGetProperty("harmless", out var h) ? h.GetInt32() : 0;
            int undetected = stats.TryGetProperty("undetected", out var u) ? u.GetInt32() : 0;
            int total = malicious + suspicious + harmless + undetected;

            return new CloudReputationResult(
                Checked: true,
                IsMalicious: malicious >= 2 || (malicious + suspicious) >= 3,
                MaliciousDetections: malicious + suspicious,
                TotalEngines: total,
                Summary: $"VirusTotal: {malicious} 악성 / {suspicious} 의심 (총 {total}개 엔진)");
        }
        catch (Exception ex)
        {
            return new CloudReputationResult(false, false, 0, 0, $"클라우드 조회 실패: {ex.Message}");
        }
    }

    private void Load()
    {
        lock (_sync)
        {
            try
            {
                if (File.Exists(IntelFilePath))
                {
                    var db = JsonSerializer.Deserialize<ThreatIntelDatabase>(File.ReadAllText(IntelFilePath));
                    if (db is not null)
                    {
                        _hashes = new HashSet<string>((db.BlockedSha256Hashes ?? new List<string>()).Select(s => s.Trim()).Where(s => s.Length > 0), StringComparer.OrdinalIgnoreCase);
                        _ips = new HashSet<string>((db.BlockedIpAddresses ?? new List<string>()).Select(s => s.Trim()).Where(s => s.Length > 0), StringComparer.OrdinalIgnoreCase);
                        _domains = new HashSet<string>((db.BlockedDomains ?? new List<string>()).Select(s => s.Trim().TrimEnd('.')).Where(s => s.Length > 0), StringComparer.OrdinalIgnoreCase);
                        _feedIps = new HashSet<string>(
                            (db.FeedBlockedIpAddresses ?? new List<string>())
                                .Select(s => s.Trim())
                                .Where(s => s.Length > 0 && (!IPAddress.TryParse(s, out var ip) || (!Engine.NetworkGuardMonitor.IsLocalOrPrivateIp(ip) && !IsProtectedInfrastructureOrCdnIp(ip)))),
                            StringComparer.OrdinalIgnoreCase);
                        _c2FeedDomains = new HashSet<string>(
                            (db.FeedBlockedDomains ?? new List<string>())
                                .Select(s => s.Trim().TrimEnd('.'))
                                .Where(s => s.Length > 0 && !IsProtectedMajorDomainOrSubdomain(s)),
                            StringComparer.OrdinalIgnoreCase);
                        LoadFeedDomainsFileLocked();
                        // Migrate legacy unsplit StevenBlack dumps (>20k entries stored in FeedBlockedDomains) out of real-time C2 set
                        if (_c2FeedDomains.Count > 20_000)
                        {
                            foreach (var d in _c2FeedDomains) _adwareFeedDomains.Add(d);
                            _c2FeedDomains.Clear();
                            _lastFeedSyncUtc = null;
                            return;
                        }
                        _lastFeedSyncUtc = db.LastFeedSyncUtc;
                        return;
                    }
                }
            }
            catch
            {
                // Preserve corrupt intel.json backup and still preserve feed_domains.txt instead of wiping!
                try { if (File.Exists(IntelFilePath)) File.Copy(IntelFilePath, IntelFilePath + ".corrupt", overwrite: true); } catch { }
            }

            // Default seed IOCs (includes known hijacked NIKKE supply-chain domain)
            _domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "insightjs.com"
            };
            LoadFeedDomainsFileLocked();
            SaveLocked();
        }
    }

    private void LoadFeedDomainsFileLocked()
    {
        try
        {
            if (File.Exists(FeedDomainsFilePath))
            {
                foreach (var line in File.ReadLines(FeedDomainsFilePath))
                {
                    var d = line.Trim().TrimEnd('.');
                    if (d.Length > 0 && !IsProtectedMajorDomainOrSubdomain(d)) _adwareFeedDomains.Add(d);
                }
            }
        }
        catch { }
    }

    private ThreatIntelDatabase BuildIntelDbSnapshotLocked() => new(
        _hashes.OrderBy(x => x).ToList(),
        _ips.OrderBy(x => x).ToList(),
        _domains.OrderBy(x => x).ToList(),
        _lastFeedSyncUtc,
        _feedIps.OrderBy(x => x).ToList(),
        _c2FeedDomains.OrderBy(x => x).ToList());

    private void SaveLocked()
    {
        // Only write lightweight intel.json (do NOT re-sort/rewrite 80k+ feed_domains.txt on single user IOC additions!)
        WriteIntelAtomic(BuildIntelDbSnapshotLocked());
    }

    private void WriteIntelAtomic(ThreatIntelDatabase db)
    {
        try
        {
            var tmp = IntelFilePath + $".{Guid.NewGuid():N}.tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(db, JsonOptions));
            File.Move(tmp, IntelFilePath, overwrite: true);
        }
        catch { }
    }

    private void WriteFeedDomainsAtomic(List<string> domains)
    {
        try
        {
            if (domains.Count == 0) return;
            domains.Sort(StringComparer.OrdinalIgnoreCase);
            var tmp = FeedDomainsFilePath + $".{Guid.NewGuid():N}.tmp";
            File.WriteAllLines(tmp, domains);
            File.Move(tmp, FeedDomainsFilePath, overwrite: true);
        }
        catch { }
    }
}
