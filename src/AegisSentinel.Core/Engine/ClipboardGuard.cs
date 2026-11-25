using System.Text.RegularExpressions;
using AegisSentinel.Core.Models;

namespace AegisSentinel.Core.Engine;

/// <summary>
/// Privacy-preserving clipboard analyzer (never logs or persists user clipboard text).
/// Detects 2025-2026 ClickFix social-engineering clipboard payloads where malicious web pages
/// copy hidden shell/script download-and-execute commands into the user's clipboard.
/// Implemented with structural command analysis so normal documentation URLs (e.g. learn.microsoft.com/powershell) never false-trigger.
/// </summary>
public sealed class ClipboardGuard
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(500);

    private static readonly Regex ShellInvocationRegex = new(
        @"(^|[\s;|&""'\\/])(powershell(\.exe)?|pwsh(\.exe)?|cmd(\.exe)?(\s+/[a-z0-9:]+)*\s*/[ckr]|mshta(\.exe)?|wscript(\.exe)?|cscript(\.exe)?|rundll32(\.exe)?)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled, RegexTimeout);

    private static readonly string[] HighConfidenceExecutionTokens =
    {
        "-enc", "-encodedcommand", "-w hidden", "-windowstyle hidden",
        "invoke-expression", "downloadstring", "downloadfile", "frombase64string",
        "net.webclient", "start-bitstransfer", "javascript:"
    };

    private static readonly Regex ShortCradleRegex = new(
        @"(\b(iex|invoke-expression)\b.*https?://|https?://.*\b(iex|invoke-expression)\b|\bmshta(\.exe)?\s+https?://)",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled, RegexTimeout);

    private static readonly Regex DirectPipeCradleRegex = new(
        @"(\b(iwr|irm|invoke-webrequest|invoke-restmethod|curl|wget)\b[^\r\n]{0,512}https?://[^\r\n]{0,512}\|\s*(iex|invoke-expression)\b)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled, RegexTimeout);

    public SecurityEvent? EvaluateClipboardText(string? text, GuardPolicy policy)
    {
        if (!policy.EnableClipboardGuard || string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var trimmed = text.Trim();
        if (trimmed.Length > 16384 || trimmed.Length < 12)
        {
            return null;
        }

        // Pure URL without whitespace is just a copied link (e.g. https://learn.microsoft.com/powershell/...), never a ClickFix command
        if ((trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
             trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) &&
            !trimmed.Any(char.IsWhiteSpace))
        {
            return null;
        }

        bool isClickFix = false;
        try
        {
            bool hasShellInvocation = ShellInvocationRegex.IsMatch(trimmed);
            bool hasExecToken = HighConfidenceExecutionTokens.Any(t => trimmed.Contains(t, StringComparison.OrdinalIgnoreCase)) ||
                                ShortCradleRegex.IsMatch(trimmed);
            isClickFix = (hasShellInvocation && hasExecToken) || DirectPipeCradleRegex.IsMatch(trimmed);
        }
        catch (RegexMatchTimeoutException) { }

        if (isClickFix)
        {
            return new SecurityEvent
            {
                Severity = ThreatSeverity.Critical,
                Category = ThreatCategory.ClipboardAttack,
                ActionTaken = SecurityActionTaken.Logged,
                Title = "ClickFix 클립보드 악성 명령 주입 탐지!",
                Description = "웹페이지 또는 외부 앱이 원격 다운로드/숨김 스크립트 실행 명령을 클립보드에 주입했습니다. Win+R 실행 창에 절대 붙여넣지 마세요!",
                RiskScore = 90,
                RiskSignals = new List<string> { "ClickFixClipboardPayload(+90)" }
            };
        }

        return null;
    }
}
