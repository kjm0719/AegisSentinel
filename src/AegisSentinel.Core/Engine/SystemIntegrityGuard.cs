using Microsoft.Win32;
using AegisSentinel.Core.Models;
using AegisSentinel.Core.Services;

namespace AegisSentinel.Core.Engine;

/// <summary>
/// Monitors critical OS integrity surfaces and AegisSentinel's own self-defense boundary:
/// 1) C:\Windows\System32\drivers\etc\hosts (DNS hijacking)
/// 2) Windows Internet Proxy settings (silent MITM proxy injection)
/// 3) Windows Defender Exclusion registry keys (malware hiding itself from Defender)
/// 4) AegisSentinel's own policy.json HMAC seal (anti-tamper self-defense)
/// </summary>
public sealed class SystemIntegrityGuard : IDisposable
{
    private readonly PolicyStore _policyStore;
    private readonly Func<GuardPolicy> _policyProvider;
    private readonly Action<GuardPolicy>? _restorePolicyAction;
    private readonly CustomRuleEngine? _customRuleEngine;
    private readonly BrowserAndPupCleaner? _browserPupCleaner;

    private string _hostsSha256 = string.Empty;
    private string _proxyBaseline = string.Empty;
    private HashSet<string> _defenderExclusionsBaseline = new(StringComparer.OrdinalIgnoreCase);
    private Timer? _pollTimer;
    private int _isChecking;
    private int _pollTick;

    public event Action<SecurityEvent>? ThreatDetected;

    public SystemIntegrityGuard(
        PolicyStore policyStore,
        Func<GuardPolicy> policyProvider,
        Action<GuardPolicy>? restorePolicyAction = null,
        CustomRuleEngine? customRuleEngine = null,
        BrowserAndPupCleaner? browserPupCleaner = null)
    {
        _policyStore = policyStore;
        _policyProvider = policyProvider;
        _restorePolicyAction = restorePolicyAction;
        _customRuleEngine = customRuleEngine;
        _browserPupCleaner = browserPupCleaner;
    }

    public void RefreshHostsBaseline()
    {
        var h = ComputeHostsHash();
        if (!string.IsNullOrEmpty(h)) _hostsSha256 = h;
    }

    public void Start()
    {
        Stop();
        _hostsSha256 = ComputeHostsHash();
        _proxyBaseline = ReadProxySettings();
        _defenderExclusionsBaseline = ReadDefenderExclusionKeys() ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        _pollTimer = new Timer(_ => PollIntegrity(), null, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(10));
    }

    public void Stop()
    {
        _pollTimer?.Dispose();
        _pollTimer = null;
    }

    public SecurityEvent? CheckPolicySelfDefense(GuardPolicy lastKnownGoodPolicy)
    {
        if (!_policyStore.VerifyIntegrity(out var reason))
        {
            bool healed = false;
            try
            {
                _policyStore.Save(lastKnownGoodPolicy);
                _restorePolicyAction?.Invoke(lastKnownGoodPolicy);
                healed = _policyStore.VerifyIntegrity(out _);
            }
            catch { }

            return new SecurityEvent
            {
                Severity = ThreatSeverity.Critical,
                Category = ThreatCategory.SelfDefenseTamper,
                ActionTaken = healed ? SecurityActionTaken.RolledBack : SecurityActionTaken.Logged,
                Title = healed
                    ? "자가 방어 경고: AegisSentinel 보안 정책 외부 무단 변조 차단!"
                    : "자가 방어 경고: AegisSentinel 보안 정책 변조 감지 (복구 권한 확인 필요)!",
                Description = healed ? $"{reason} 정상 정책으로 자동 복구되었습니다." : $"{reason} 디스크 자동 복구에 실패했습니다.",
                TargetPath = _policyStore.PolicyFilePath,
                RiskScore = 100,
                RiskSignals = new List<string> { "SelfDefensePolicyTampered(+100)" }
            };
        }

        return null;
    }

    public SecurityEvent? CheckRulesSelfDefense()
    {
        if (_customRuleEngine is null) return null;
        if (!_customRuleEngine.VerifyIntegrity(out var reason))
        {
            // Restore last-known-good in-memory custom rules (falling back to defaults if empty)
            var lastGood = _customRuleEngine.GetRulesSnapshot();
            if (lastGood.Count > 0) _customRuleEngine.SaveAndReload(lastGood);
            else _customRuleEngine.Reload();

            bool healed = _customRuleEngine.VerifyIntegrity(out _);
            return new SecurityEvent
            {
                Severity = ThreatSeverity.Critical,
                Category = ThreatCategory.SelfDefenseTamper,
                ActionTaken = healed ? SecurityActionTaken.RolledBack : SecurityActionTaken.Logged,
                Title = "자가 방어 경고: AegisSentinel 탐지 규칙(rules.json) 외부 무단 변조 차단!",
                Description = healed ? $"{reason} 정상 탐지 규칙으로 자동 복구되었습니다." : $"{reason} 디스크 자동 복구에 실패했습니다.",
                TargetPath = _customRuleEngine.RulesFilePath,
                RiskScore = 100,
                RiskSignals = new List<string> { "SelfDefenseRulesTampered(+100)" }
            };
        }

        return null;
    }

    public SecurityEvent? CheckPupRulesSelfDefense()
    {
        if (_browserPupCleaner is null) return null;
        if (!_browserPupCleaner.VerifyIntegrity(out var reason))
        {
            _browserPupCleaner.Reload();
            bool healed = _browserPupCleaner.VerifyIntegrity(out _);
            return new SecurityEvent
            {
                Severity = ThreatSeverity.Critical,
                Category = ThreatCategory.SelfDefenseTamper,
                ActionTaken = healed ? SecurityActionTaken.RolledBack : SecurityActionTaken.Logged,
                Title = "자가 방어 경고: AegisSentinel PUP 룰(pup_rules.json) 외부 무단 변조 차단!",
                Description = healed ? $"{reason} 기본 PUP 탐지 룰로 자동 복구되었습니다." : $"{reason} 자동 복구에 실패했습니다.",
                TargetPath = _browserPupCleaner.PupRulesFilePath,
                RiskScore = 100,
                RiskSignals = new List<string> { "SelfDefensePupRulesTampered(+100)" }
            };
        }

        return null;
    }

    public static SecurityEvent? EvaluateHostsDiff(string previousHash, string currentHash, string hostsPath)
    {
        if (string.IsNullOrEmpty(previousHash) || string.IsNullOrEmpty(currentHash) ||
            previousHash.Equals(currentHash, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return new SecurityEvent
        {
            Severity = ThreatSeverity.High,
            Category = ThreatCategory.SystemIntegrityTamper,
            ActionTaken = SecurityActionTaken.Logged,
            Title = "Windows HOSTS 파일 무단 변조(DNS 하이재킹 의심) 탐지",
            Description = $"시스템 HOSTS 파일({hostsPath})의 내용이 변경되었습니다. 피싱/C2 리다이렉션 여부를 즉시 확인하세요.",
            TargetPath = hostsPath,
            RiskScore = 80,
            RiskSignals = new List<string> { "HostsFileModified(+80)" }
        };
    }

    public static SecurityEvent? EvaluateProxyDiff(string previousProxy, string currentProxy)
    {
        if (string.Equals(previousProxy, currentProxy, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        // Alert when ProxyEnable transitions to enabled (1) or PAC AutoConfigURL is injected/changed
        var parts = currentProxy.Split('|');
        bool proxyEnabled = parts.Length >= 1 && parts[0] == "1";
        string server = parts.Length >= 2 ? parts[1] : string.Empty;
        string pacUrl = parts.Length >= 3 ? parts[2] : string.Empty;

        if (!proxyEnabled && string.IsNullOrWhiteSpace(pacUrl))
        {
            return null;
        }

        var endpoint = !string.IsNullOrWhiteSpace(pacUrl)
            ? (string.IsNullOrWhiteSpace(server) ? $"PAC:{pacUrl}" : $"{server} | PAC:{pacUrl}")
            : server;
        bool isLocalLoopbackOnly = string.IsNullOrWhiteSpace(pacUrl) &&
                                   !string.IsNullOrWhiteSpace(server) &&
                                   (server.StartsWith("127.0.0.1:", StringComparison.Ordinal) ||
                                    server.StartsWith("localhost:", StringComparison.OrdinalIgnoreCase) ||
                                    server.StartsWith("http=127.0.0.1:", StringComparison.OrdinalIgnoreCase) ||
                                    server.StartsWith("https=127.0.0.1:", StringComparison.OrdinalIgnoreCase));
        int score = isLocalLoopbackOnly ? 60 : 80;
        return new SecurityEvent
        {
            Severity = isLocalLoopbackOnly ? ThreatSeverity.Medium : ThreatSeverity.High,
            Category = ThreatCategory.SystemIntegrityTamper,
            ActionTaken = SecurityActionTaken.Logged,
            Title = isLocalLoopbackOnly
                ? "로컬 루프백 인터넷 프록시 활성화 감지"
                : "시스템 인터넷 프록시(MITM 가로채기 의심) 활성화 탐지",
            Description = $"Windows 프록시/PAC 설정이 활성화되었습니다: {endpoint}",
            TargetPath = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            RemoteEndpoint = endpoint,
            RiskScore = score,
            RiskSignals = new List<string> { $"WinInetProxyHijack(+{score})" }
        };
    }

    public static SecurityEvent? EvaluateDefenderExclusionDiff(
        IReadOnlySet<string> previous,
        IReadOnlySet<string> current)
    {
        var added = current.Where(x => !previous.Contains(x)).ToList();
        if (added.Count == 0)
        {
            return null;
        }

        return new SecurityEvent
        {
            Severity = ThreatSeverity.Critical,
            Category = ThreatCategory.SystemIntegrityTamper,
            ActionTaken = SecurityActionTaken.Logged,
            Title = "경고: Windows Defender 검사 예외 항목 무단 추가 탐지!",
            Description = $"새 Defender 예외가 등록되었습니다: {string.Join(", ", added.Take(5))}",
            TargetPath = @"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions",
            RiskScore = 95,
            RiskSignals = new List<string> { "DefenderExclusionInjected(+95)" }
        };
    }

    private void PollIntegrity()
    {
        if (Interlocked.Exchange(ref _isChecking, 1) == 1) return;

        try
        {
            int tick = Interlocked.Increment(ref _pollTick);
            if (PowerProfileHelper.IsOnBatteryPower && (tick & 1) == 1)
            {
                return; // 20s cadence on laptop battery (10s on AC); ETW Registry remains real-time!
            }

            var policy = _policyProvider();
            if (!policy.EnableSystemIntegrityGuard) return;

            // 1. Self-defense HMAC check on policy.json, rules.json & pup_rules.json
            var selfAlert = CheckPolicySelfDefense(policy);
            if (selfAlert is not null) ThreatDetected?.Invoke(selfAlert);

            var rulesAlert = CheckRulesSelfDefense();
            if (rulesAlert is not null) ThreatDetected?.Invoke(rulesAlert);

            var pupAlert = CheckPupRulesSelfDefense();
            if (pupAlert is not null) ThreatDetected?.Invoke(pupAlert);

            // 2. Hosts file check (NEVER overwrite baseline with "" on transient lock error!)
            var hostsPath = GetHostsFilePath();
            var currentHostsHash = ComputeHostsHash();
            if (!string.IsNullOrEmpty(currentHostsHash))
            {
                var hostsAlert = EvaluateHostsDiff(_hostsSha256, currentHostsHash, hostsPath);
                _hostsSha256 = currentHostsHash;
                if (hostsAlert is not null) ThreatDetected?.Invoke(hostsAlert);
            }

            // 3. Proxy hijack check
            var currentProxy = ReadProxySettings();
            var proxyAlert = EvaluateProxyDiff(_proxyBaseline, currentProxy);
            _proxyBaseline = currentProxy;
            if (proxyAlert is not null) ThreatDetected?.Invoke(proxyAlert);

            // 4. Defender exclusion tampering check (skip baseline overwrite on transient read error!)
            var currentExclusions = ReadDefenderExclusionKeys();
            if (currentExclusions is not null && (_defenderExclusionsBaseline.Count > 0 || currentExclusions.Count > 0))
            {
                var exclAlert = EvaluateDefenderExclusionDiff(_defenderExclusionsBaseline, currentExclusions);
                _defenderExclusionsBaseline = currentExclusions;
                if (exclAlert is not null) ThreatDetected?.Invoke(exclAlert);
            }

            // 5. UAC Bypass Registry Hijack check & auto-rollback (ms-settings / mscfile / CurVer)
            var uacAlert = CheckAndCleanUacBypassRegistryKeys();
            if (uacAlert is not null) ThreatDetected?.Invoke(uacAlert);
        }
        catch { }
        finally
        {
            Interlocked.Exchange(ref _isChecking, 0);
        }
    }

    private static string GetHostsFilePath() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");

    /// <summary>
    /// One-click rollback for hijacked WinInet MITM proxy settings (sets ProxyEnable = 0 and deletes AutoConfigURL PAC script).
    /// </summary>
    public static bool TryDisableHijackedProxy()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", writable: true);
            if (key is null) return false;
            key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
            key.DeleteValue("ProxyServer", throwOnMissingValue: false);
            key.DeleteValue("AutoConfigURL", throwOnMissingValue: false);
            _ = Native.NativeMethods.InternetSetOption(IntPtr.Zero, Native.NativeMethods.INTERNET_OPTION_SETTINGS_CHANGED, IntPtr.Zero, 0);
            _ = Native.NativeMethods.InternetSetOption(IntPtr.Zero, Native.NativeMethods.INTERNET_OPTION_REFRESH, IntPtr.Zero, 0);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static SecurityEvent? CheckAndCleanUacBypassRegistryKeys()
    {
        string[] uacHijackSubKeys =
        {
            @"Software\Classes\ms-settings\Shell\Open\command",
            @"Software\Classes\ms-settings\CurVer",
            @"Software\Classes\mscfile\Shell\Open\command"
        };

        var foundKeys = new List<string>();
        var foundCmds = new List<string>();
        bool allCleaned = true;

        foreach (var subKey in uacHijackSubKeys)
        {
            try
            {
                string? cmd;
                using (var key = Registry.CurrentUser.OpenSubKey(subKey, false))
                {
                    cmd = key?.GetValue("")?.ToString();
                }

                if (!string.IsNullOrWhiteSpace(cmd))
                {
                    foundKeys.Add($"HKCU\\{subKey}");
                    foundCmds.Add(cmd);

                    var rootIdx = subKey.IndexOf("\\Shell", StringComparison.OrdinalIgnoreCase);
                    if (rootIdx < 0) rootIdx = subKey.IndexOf("\\CurVer", StringComparison.OrdinalIgnoreCase);
                    var treeToDelete = rootIdx > 0 ? subKey[..rootIdx] : subKey;
                    try
                    {
                        Registry.CurrentUser.DeleteSubKeyTree(treeToDelete, throwOnMissingSubKey: false);
                    }
                    catch
                    {
                        allCleaned = false;
                    }
                }
            }
            catch { }
        }

        if (foundKeys.Count == 0) return null;

        return new SecurityEvent
        {
            Severity = ThreatSeverity.Critical,
            Category = ThreatCategory.PrivilegeEscalation,
            ActionTaken = allCleaned ? SecurityActionTaken.RolledBack : SecurityActionTaken.Logged,
            Title = "UAC 권한 상승 우회 레지스트리(ms-settings/CurVer/mscfile) 탐지 및 자동 제거!",
            Description = $"{string.Join(", ", foundKeys)}에 등록된 UAC 우회 명령('{string.Join(" | ", foundCmds)}')을 감지해 {(allCleaned ? "즉시 롤백했습니다." : "제거를 시도했습니다.")}",
            TargetPath = foundKeys[0],
            CommandLine = string.Join(" | ", foundCmds),
            RiskScore = 95,
            RiskSignals = new List<string> { "UacRegistryHijackRolledBack(+95)" }
        };
    }

    private static string ComputeHostsHash()
    {
        try
        {
            var path = GetHostsFilePath();
            return File.Exists(path) ? SignatureVerifier.ComputeSha256(path) : string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string ReadProxySettings()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", false);
            if (key is null) return "0||";
            int enabled = key.GetValue("ProxyEnable") is int v && v != 0 ? 1 : 0;
            string server = key.GetValue("ProxyServer")?.ToString() ?? string.Empty;
            string pacUrl = key.GetValue("AutoConfigURL")?.ToString() ?? string.Empty;
            return $"{enabled}|{server}|{pacUrl}";
        }
        catch
        {
            return "0||";
        }
    }

    private static HashSet<string>? ReadDefenderExclusionKeys()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        bool anyOpened = false;
        string[] baseRoots =
        {
            @"SOFTWARE\Microsoft\Windows Defender\Exclusions",
            @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions"
        };
        foreach (var baseRoot in baseRoots)
        {
            foreach (var sub in new[] { "Paths", "Processes", "Extensions" })
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey($@"{baseRoot}\{sub}", false);
                    if (key is null) continue;
                    anyOpened = true;
                    foreach (var name in key.GetValueNames())
                    {
                        set.Add($"{sub}:{name}");
                    }
                }
                catch
                {
                    // Reading Defender Exclusions requires Administrator rights.
                }
            }
        }
        return anyOpened ? set : null;
    }

    public void Dispose()
    {
        Stop();
    }
}
