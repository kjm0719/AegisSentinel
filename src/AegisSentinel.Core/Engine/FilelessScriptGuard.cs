using System.Diagnostics.Eventing.Reader;
using System.Text;
using System.Text.RegularExpressions;
using AegisSentinel.Core.Models;
using AegisSentinel.Core.Services;

namespace AegisSentinel.Core.Engine;

/// <summary>
/// Watches Windows PowerShell Script Block Logging (Event ID 4104) with an AI-obfuscation
/// normalization pipeline (backtick stripping, string-concat folding, inline Base64 decoding,
/// and statistical obfuscation scoring) plus Windows Defender threat events (1116/1117/5001).
/// </summary>
public sealed class FilelessScriptGuard : IDisposable
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(1500);

    private static readonly (Regex Pattern, string Signal, int Weight, string Label)[] ScriptRules =
    {
        (new Regex(@"(AmsiUtils|amsiInitFailed|AmsiScanBuffer|AmsiContext)", RegexOptions.IgnoreCase | RegexOptions.Compiled, RegexTimeout),
            "AmsiBypassAttempt", 90, "AMSI 보안 우회(메모리 패치) 시도"),
        (new Regex(@"(VirtualAlloc|CreateRemoteThread|WriteProcessMemory|NtUnmapViewOfSection|\[Reflection\.Assembly\]::Load\s*\()", RegexOptions.IgnoreCase | RegexOptions.Compiled, RegexTimeout),
            "InMemoryInjection", 85, "파일리스 메모리 인젝션/리플렉션 로드"),
        (new Regex(@"(Add-MpPreference\s+[^\r\n]{0,256}-Exclusion|Set-MpPreference\s+[^\r\n]{0,256}-DisableRealtimeMonitoring|Uninstall-WindowsFeature[^\r\n]{0,128}Defender)", RegexOptions.IgnoreCase | RegexOptions.Compiled, RegexTimeout),
            "DefenderTampering", 90, "Windows Defender 무력화/예외 주입 시도"),
        (new Regex(string.Concat("(CryptUnprotectData|ProtectedData\\]::Unprotect|Login", "\\s+", "Data.{0,200}Local", "\\s+", "State|lsass\\.dmp)"), RegexOptions.IgnoreCase | RegexOptions.Compiled, RegexTimeout),
            "CredentialDumpingScript", 85, "자격증명/브라우저 DPAPI 복호화 탈취 스크립트"),
        (new Regex(@"((DownloadString|DownloadData|Invoke-WebRequest|\biwr\b|\bcurl\b).{0,400}\b(Invoke-Expression|IEX)\b|FromBase64String.{0,400}\b(Invoke-Expression|IEX)\b)", RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled, RegexTimeout),
            "FilelessDownloadExec", 75, "원격 파일리스 스크립트 다운로드 및 즉시 실행")
    };

    private static readonly Regex StringConcatRegex = new(
        @"(['""])([A-Za-z0-9_\-.:/\\]{1,40})\1\s*\+\s*(['""])([A-Za-z0-9_\-.:/\\]{1,40})\3",
        RegexOptions.Compiled, RegexTimeout);

    private static readonly Regex Base64SegmentRegex = new(
        @"[A-Za-z0-9+/]{28,}={0,2}",
        RegexOptions.Compiled, RegexTimeout);

    // Match printable ASCII char casts (32..126) used to spell obfuscated commands, ignoring terminal control chars like [char]27 / [char]7 / [char]0
    private static readonly Regex CharCastRegex = new(
        @"\[char\]\s*(?:3[2-9]|[4-9]\d|1[01]\d|12[0-6])\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled, RegexTimeout);

    private readonly Func<GuardPolicy> _policyProvider;
    private EventLogWatcher? _powershellWatcher;
    private EventLogWatcher? _defenderWatcher;

    public event Action<SecurityEvent>? ThreatDetected;

    public FilelessScriptGuard(Func<GuardPolicy> policyProvider)
    {
        _policyProvider = policyProvider;
    }

    public void Start()
    {
        Stop();

        TryAttachWatcher(
            "Microsoft-Windows-PowerShell/Operational",
            "*[System[(EventID=4104)]]",
            OnPowerShellScriptEvent,
            out _powershellWatcher);

        TryAttachWatcher(
            "Microsoft-Windows-Windows Defender/Operational",
            "*[System[(EventID=1116 or EventID=1117 or EventID=5001)]]",
            OnDefenderEvent,
            out _defenderWatcher);
    }

    public void Stop()
    {
        DisposeWatcher(ref _powershellWatcher);
        DisposeWatcher(ref _defenderWatcher);
    }

    /// <summary>
    /// Normalizes common AI / polymorphic PowerShell obfuscation techniques before rule matching:
    /// 1) Backtick insertion removal (I`nv`oke -> Invoke)
    /// 2) Repeated literal string concatenation folding ('Am'+'si' -> 'Amsi')
    /// 3) Inline Base64 UTF-8 / UTF-16LE payload decoding
    /// </summary>
    public static string NormalizeObfuscatedScript(string rawScript)
    {
        if (string.IsNullOrWhiteSpace(rawScript))
        {
            return string.Empty;
        }

        // 1. Strip PowerShell backtick escape evasion
        var normalized = rawScript.Replace("`", string.Empty);

        // 2. Iteratively fold literal string concatenations ("Am"+"si"+"Scan"+"Buffer")
        try
        {
            for (int pass = 0; pass < 6; pass++)
            {
                var next = StringConcatRegex.Replace(normalized, m => $"\"{m.Groups[2].Value}{m.Groups[4].Value}\"");
                if (next == normalized) break;
                normalized = next;
            }
        }
        catch (RegexMatchTimeoutException) { }

        // 3. Decode inline Base64 segments (UTF-8 and UTF-16LE) and append printable text for inspection
        var decodedExtras = new StringBuilder();
        try
        {
            foreach (Match m in Base64SegmentRegex.Matches(normalized).Cast<Match>().Take(8))
            {
                var candidate = m.Value;
                if (candidate.Length % 4 != 0) continue;
                try
                {
                    var bytes = Convert.FromBase64String(candidate);
                    if (bytes.Length < 12) continue;

                    var utf8 = Encoding.UTF8.GetString(bytes);
                    if (IsMostlyPrintable(utf8))
                    {
                        decodedExtras.AppendLine().Append(utf8);
                    }

                    if (bytes.Length % 2 == 0)
                    {
                        var utf16 = Encoding.Unicode.GetString(bytes);
                        if (IsMostlyPrintable(utf16))
                        {
                            decodedExtras.AppendLine().Append(utf16);
                        }
                    }
                }
                catch { }
            }
        }
        catch (RegexMatchTimeoutException) { }

        return decodedExtras.Length > 0 ? normalized + "\n" + decodedExtras : normalized;
    }

    private static readonly Regex MidIdentifierBacktickRegex = new(
        @"[A-Za-z0-9]`(?![nrt0abefv\s""'$])[A-Za-z0-9]",
        RegexOptions.Compiled, RegexTimeout);

    public static (int Score, List<string> Signals) ComputeObfuscationHeuristics(string rawScript)
    {
        var signals = new List<string>();
        int score = 0;

        try
        {
            // Count ONLY mid-identifier evasion backticks (e.g. I`nv`oke), never normal `n / `r / `t / `e string escapes!
            int evasionBackticks = MidIdentifierBacktickRegex.Matches(rawScript).Count;
            if (evasionBackticks >= 4)
            {
                score += 45;
                signals.Add($"BacktickObfuscation:{evasionBackticks}(+45)");
            }

            int charCasts = CharCastRegex.Matches(rawScript).Count;
            if (charCasts >= 6 && rawScript.Contains("-join", StringComparison.OrdinalIgnoreCase))
            {
                score += 65;
                signals.Add($"CharArrayJoinObfuscation:{charCasts}(+65)");
            }

            int concatCount = StringConcatRegex.Matches(rawScript).Count;
            if (concatCount >= 5)
            {
                score += 35;
                signals.Add($"StringSplitObfuscation:{concatCount}(+35)");
            }
        }
        catch (RegexMatchTimeoutException) { }

        return (Math.Min(85, score), signals);
    }

    public static SecurityEvent? AnalyzeScriptBlock(string scriptText, int pid, GuardPolicy policy, bool ignorePolicyToggle = false)
    {
        if ((!ignorePolicyToggle && !policy.EnableFilelessScriptGuard) || string.IsNullOrWhiteSpace(scriptText))
        {
            return null;
        }

        if (InternalHelperProcessRegistry.IsInternalHelper(pid))
        {
            return null;
        }

        var normalized = NormalizeObfuscatedScript(scriptText);
        var (obfScore, obfSignals) = ComputeObfuscationHeuristics(scriptText);

        var matchedSignals = new List<string>(obfSignals);
        var matchedLabels = new List<string>();
        int totalWeight = obfScore;

        foreach (var (pattern, signal, weight, label) in ScriptRules)
        {
            try
            {
                if (pattern.IsMatch(normalized))
                {
                    matchedSignals.Add($"{signal}(+{weight})");
                    matchedLabels.Add(label);
                    totalWeight = Math.Min(100, totalWeight + weight);
                }
            }
            catch (RegexMatchTimeoutException) { }
        }

        // Pure [char] integer-array -join obfuscation hides the API/IEX keyword itself inside integer codes
        bool hasCharJoinObfuscation = obfSignals.Any(s => s.StartsWith("CharArrayJoinObfuscation", StringComparison.Ordinal));
        if (hasCharJoinObfuscation && matchedLabels.Count == 0)
        {
            matchedLabels.Add("AI/다형성 문자배열 난독화 우회 기법");
        }

        if (matchedLabels.Count == 0)
        {
            return null;
        }

        var snippet = scriptText.Length > 260 ? scriptText[..260] + "..." : scriptText;
        var primaryLabel = matchedLabels.Count > 0 ? matchedLabels[0] : "고위험 난독화 스크립트";

        return new SecurityEvent
        {
            Severity = totalWeight >= 75 ? ThreatSeverity.Critical : ThreatSeverity.High,
            Category = ThreatCategory.FilelessScript,
            ActionTaken = SecurityActionTaken.Logged,
            Title = $"파일리스/메모리 스크립트 공격 탐지: {primaryLabel}",
            Description = $"역난독화(De-obfuscation) 분석 결과 위험 행위({string.Join(", ", matchedLabels.Distinct())})가 탐지되었습니다.",
            ProcessId = pid,
            ProcessName = "powershell",
            CommandLine = snippet,
            RiskScore = Math.Clamp(totalWeight, 0, 100),
            RiskSignals = matchedSignals
        };
    }

    private static bool IsMostlyPrintable(string s)
    {
        if (s.Length < 8) return false;
        int printable = 0;
        foreach (char c in s)
        {
            if ((c >= 32 && c <= 126) || c is '\r' or '\n' or '\t')
            {
                printable++;
            }
        }
        return (double)printable / s.Length >= 0.85;
    }

    private void OnPowerShellScriptEvent(object? sender, EventRecordWrittenEventArgs args)
    {
        try
        {
            if (args.EventRecord is null) return;
            var policy = _policyProvider();
            var scriptText = args.EventRecord.Properties.Count >= 3
                ? args.EventRecord.Properties[2]?.Value?.ToString() ?? string.Empty
                : args.EventRecord.FormatDescription() ?? string.Empty;

            int pid = args.EventRecord.ProcessId ?? 0;
            var alert = AnalyzeScriptBlock(scriptText, pid, policy);
            if (alert is not null)
            {
                ThreatDetected?.Invoke(alert);
            }
        }
        catch { }
    }

    private void OnDefenderEvent(object? sender, EventRecordWrittenEventArgs args)
    {
        try
        {
            if (args.EventRecord is null || !_policyProvider().EnableFilelessScriptGuard) return;
            var desc = args.EventRecord.FormatDescription() ?? $"Windows Defender 보안 이벤트 ID {args.EventRecord.Id}";
            var id = args.EventRecord.Id;
            var title = id switch
            {
                5001 => "경고: Windows Defender 실시간 보호가 비활성화됨!",
                1116 => "Windows Defender 악성코드 탐지 연동",
                1117 => "Windows Defender 악성코드 차단 완료",
                _ => $"Windows Defender 이벤트 ({id})"
            };

            // EventRecord.ProcessId is the logger PID (MsMpEng.exe) — always use ProcessId = 0 so Defender itself is never targeted!
            ThreatDetected?.Invoke(new SecurityEvent
            {
                Severity = id == 5001 ? ThreatSeverity.Critical : ThreatSeverity.High,
                Category = ThreatCategory.SystemHardening,
                ActionTaken = id == 1117 ? SecurityActionTaken.Quarantined : SecurityActionTaken.Logged,
                Title = title,
                Description = desc.Length > 350 ? desc[..350] + "..." : desc,
                ProcessId = 0,
                ProcessName = "WindowsDefender",
                RiskScore = id == 5001 ? 95 : 80
            });
        }
        catch { }
    }

    private static void TryAttachWatcher(
        string logName,
        string xpathQuery,
        EventHandler<EventRecordWrittenEventArgs> handler,
        out EventLogWatcher? watcher)
    {
        watcher = null;
        try
        {
            var query = new EventLogQuery(logName, PathType.LogName, xpathQuery);
            watcher = new EventLogWatcher(query);
            watcher.EventRecordWritten += handler;
            watcher.Enabled = true;
        }
        catch
        {
            watcher?.Dispose();
            watcher = null;
        }
    }

    private static void DisposeWatcher(ref EventLogWatcher? watcher)
    {
        if (watcher is null) return;
        try
        {
            watcher.Enabled = false;
            watcher.Dispose();
        }
        catch { }
        finally
        {
            watcher = null;
        }
    }

    public void Dispose()
    {
        Stop();
    }
}
