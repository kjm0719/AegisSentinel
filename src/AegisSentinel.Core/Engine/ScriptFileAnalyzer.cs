using System.Text.RegularExpressions;
using AegisSentinel.Core.Models;

namespace AegisSentinel.Core.Engine;

public sealed record ScriptStaticResult(
    bool IsSuspicious,
    int RiskScore,
    IReadOnlyList<string> Reasons);

/// <summary>
/// Pre-execution static analyzer for script files (.ps1, .bat, .cmd, .vbs, .js, .hta)
/// dropped in Downloads, USB drives, or inside .zip archives.
/// Reuses FilelessScriptGuard's AI de-obfuscation pipeline for PowerShell and adds
/// structural dropper/obfuscation heuristics for VBScript, JScript, HTA, and Batch scripts.
/// </summary>
public static class ScriptFileAnalyzer
{
    private static readonly HashSet<string> SupportedScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".wsf", ".sct"
    };

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(1500);

    private static readonly Regex BatchDownloadExecRegex = new(
        @"(powershell(\.exe)?|pwsh(\.exe)?|mshta(\.exe)?|certutil(\.exe)?|bitsadmin(\.exe)?|curl(\.exe)?)\s+[^\r\n]{0,512}(https?://|-enc(odedcommand)?\s+[A-Za-z0-9+/=]{16,}|-w\s+hidden|-windowstyle\s+hidden|urlcache\s+-split|downloadstring|frombase64string|\biex\b|invoke-expression)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled, RegexTimeout);

    private static readonly Regex ScriptComObjectRegex = new(
        @"(WScript\.Shell|Shell\.Application|Scripting\.FileSystemObject|MSXML2\.(Server)?XMLHTTP|WinHttp\.WinHttpRequest|ADODB\.Stream)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled, RegexTimeout);

    private static readonly Regex ScriptExecutionSinkRegex = new(
        @"(\.Run\s*\(|\.Exec\s*\(|ShellExecute|SaveToFile|\beval\s*\(|ExecuteGlobal|https?://|powershell|cmd\.exe|mshta)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled, RegexTimeout);

    private static readonly Regex RansomwareShadowTamperRegex = new(
        @"(vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|wbadmin(\.exe)?\s+delete\s+catalog|bcdedit(\.exe)?\s+/set\s+\{default\}\s+recoveryenabled\s+no|Add-MpPreference\s+[^\r\n]{0,256}-Exclusion|Set-MpPreference\s+[^\r\n]{0,256}-Disable(RealtimeMonitoring|BehaviorMonitoring)|netsh(\.exe)?\s+advfirewall\s+set\s+[^\r\n]{0,128}state\s+off|wevtutil(\.exe)?\s+cl\s+(Security|System|Application))",
        RegexOptions.IgnoreCase | RegexOptions.Compiled, RegexTimeout);

    private static readonly Regex ChrObfuscationRegex = new(
        @"(ChrW?\s*\(\s*\d+\s*\)|String\.fromCharCode\s*\()",
        RegexOptions.IgnoreCase | RegexOptions.Compiled, RegexTimeout);

    public static bool IsSupportedScriptExtension(string? ext) =>
        !string.IsNullOrWhiteSpace(ext) && SupportedScriptExtensions.Contains(ext);

    public static ScriptStaticResult AnalyzeFile(string filePath, GuardPolicy policy)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return new ScriptStaticResult(false, 0, Array.Empty<string>());
        }

        var ext = Path.GetExtension(filePath);
        if (!IsSupportedScriptExtension(ext))
        {
            return new ScriptStaticResult(false, 0, Array.Empty<string>());
        }

        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            int toRead = (int)Math.Min(256 * 1024, fs.Length);
            if (toRead <= 0)
            {
                return new ScriptStaticResult(false, 0, Array.Empty<string>());
            }

            var buffer = new byte[toRead];
            int read = fs.Read(buffer, 0, toRead);
            var text = DecodeScriptBytes(buffer.AsSpan(0, read));
            return AnalyzeScriptContent(text, ext, policy);
        }
        catch
        {
            return new ScriptStaticResult(false, 0, Array.Empty<string>());
        }
    }

    public static string DecodeScriptBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty) return string.Empty;

        // 1. UTF-16LE / UTF-16BE / UTF-8 BOM detection
        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
        {
            return System.Text.Encoding.Unicode.GetString(bytes[2..]);
        }
        if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF)
        {
            return System.Text.Encoding.BigEndianUnicode.GetString(bytes[2..]);
        }
        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
        {
            return System.Text.Encoding.UTF8.GetString(bytes[3..]);
        }

        // 2. BOM-less UTF-16LE heuristic (PowerShell / WSH / mshta natively execute UTF-16LE without BOM)
        if (bytes.Length >= 8)
        {
            int samplePairs = Math.Min(bytes.Length / 2, 64);
            int oddNulls = 0;
            for (int i = 0; i < samplePairs; i++)
            {
                if (bytes[(i * 2) + 1] == 0 && bytes[i * 2] != 0) oddNulls++;
            }
            if (oddNulls >= samplePairs * 0.6)
            {
                int evenLen = bytes.Length & ~1;
                return System.Text.Encoding.Unicode.GetString(bytes[..evenLen]);
            }
        }

        return System.Text.Encoding.UTF8.GetString(bytes);
    }

    public static ScriptStaticResult AnalyzeScriptContent(string scriptText, string extension, GuardPolicy policy)
    {
        if (string.IsNullOrWhiteSpace(scriptText))
        {
            return new ScriptStaticResult(false, 0, Array.Empty<string>());
        }

        var extLower = extension.ToLowerInvariant();
        var reasons = new List<string>();
        int score = 0;

        // 1. PowerShell (.ps1) uses full AI de-obfuscation & ScriptBlock rule engine
        // Pass ignorePolicyToggle: true so static disk/ZIP .ps1 scanning still runs even if real-time EventLog 4104 toggle is off!
        if (extLower == ".ps1")
        {
            var psAlert = FilelessScriptGuard.AnalyzeScriptBlock(scriptText, pid: 0, policy, ignorePolicyToggle: true);
            if (psAlert is not null)
            {
                score = Math.Max(score, psAlert.RiskScore);
                reasons.Add($"PowerShell 정적 악성 패턴 탐지: {psAlert.Title}");
            }
        }

        // 2. Always normalize Batch caret (^) escape obfuscation (e.g., p^o^w^e^r^s^h^e^l^l or m^s^h^t^a)
        // before running rule matching, and add obfuscation bonus when caret density is abnormally high.
        var normalized = scriptText;
        if (extLower is ".bat" or ".cmd")
        {
            int caretCount = scriptText.Count(c => c == '^');
            if (caretCount > 0)
            {
                normalized = scriptText.Replace("^", string.Empty);
            }
            if (caretCount >= 8)
            {
                score += 45;
                reasons.Add($"배치 스크립트 캐럿(^) 다형성 난독화 탐지 ({caretCount}회)");
            }
        }

        try
        {
            // 3. Ransomware recovery deletion / Defender / Firewall disable inside script
            if (RansomwareShadowTamperRegex.IsMatch(normalized))
            {
                score = Math.Max(score, 95);
                reasons.Add("스크립트 내 복구 삭제(ShadowCopy)/Defender/방화벽 무력화 명령 탐지");
            }

            // 4. Batch/PS1/HTA/VBS remote download & hidden execution cradle
            // (Skip minified single-line web .js bundles where unrelated strings appear on one line; .js is inspected by COM/YARA rules)
            if (extLower != ".js" && BatchDownloadExecRegex.IsMatch(normalized))
            {
                score = Math.Max(score, 85);
                reasons.Add($"스크립트({extension}) 내 원격 다운로드/난독화 실행 명령 탐지");
            }

            // 5. VBS / JS / HTA / WSF / SCT COM Dropper & Downloader patterns
            if (extLower is ".vbs" or ".js" or ".hta" or ".wsf" or ".sct")
            {
                bool hasCom = ScriptComObjectRegex.IsMatch(normalized);
                bool hasSink = ScriptExecutionSinkRegex.IsMatch(normalized);
                if (hasCom && hasSink)
                {
                    score = Math.Max(score, 85);
                    reasons.Add($"스크립트({extension}) COM 셸/HTTP 드로퍼 실행 체인 탐지");
                }

                int chrCount = ChrObfuscationRegex.Count(normalized);
                // For .js, require a Windows WSH COM object or eval()+shell sink alongside fromCharCode
                // so minified web frontend bundles (which contain license URLs / RegExp.exec) never false-trigger!
                bool hasJsMaliciousEvalSink = extLower == ".js" &&
                    Regex.IsMatch(normalized, @"\beval\s*\(", RegexOptions.IgnoreCase, RegexTimeout) &&
                    Regex.IsMatch(normalized, @"(ActiveXObject|WScript|powershell|cmd\.exe|mshta|CreateObject)", RegexOptions.IgnoreCase, RegexTimeout);
                if (chrCount >= 10 && (extLower != ".js" || hasCom || hasJsMaliciousEvalSink))
                {
                    score = Math.Min(100, Math.Max(score, 65) + 15);
                    reasons.Add($"스크립트({extension}) 문자코드(Chr/fromCharCode) 난독화 탐지 ({chrCount}회)");
                }
            }
        }
        catch (RegexMatchTimeoutException)
        {
            // Guard against ReDoS on huge minified scripts
        }

        score = Math.Clamp(score, 0, 100);
        return new ScriptStaticResult(score >= 55, score, reasons);
    }
}
