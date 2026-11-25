using System.Buffers.Binary;
using System.Text;
using System.Text.RegularExpressions;

namespace AegisSentinel.Core.Engine;

public sealed record LnkAnalysisResult(
    bool IsLnkFile,
    bool IsMaliciousOrSuspicious,
    int RiskScore,
    string ExtractedCommand,
    IReadOnlyList<string> Reasons);

/// <summary>
/// Pure C# binary parser for Windows Shortcut (.LNK) files and spear-phishing disk/help containers
/// (.ISO, .VHD, .VHDX, .IMG, .CHM) heavily used by North Korean APT groups (Kimsuky, Lazarus, ScarCruft).
/// </summary>
public static class LnkAndContainerAnalyzer
{
    private static readonly HashSet<string> DangerousContainerExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".iso", ".vhd", ".vhdx", ".img", ".chm"
    };

    private static readonly string[] SuspiciousLnkTargets =
    {
        "powershell", "pwsh", "cmd.exe", "\\cmd ", "mshta", "wscript", "cscript",
        "rundll32", "regsvr32", "certutil", "bitsadmin", "findstr", "curl.exe",
        "Invoke-Expression", "DownloadString", "FromBase64String",
        "Users\\Public", "AppData\\Local\\Temp"
    };

    private static readonly Regex LnkBoundaryFlagsRegex = new(
        @"(\biex\b|(?:^|\s)-enc(?:odedcommand)?\b)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex WhitespacePaddingRegex = new(@"\s{35,}", RegexOptions.Compiled);

    public static bool IsSpearPhishingContainer(string filePath)
    {
        var ext = Path.GetExtension(filePath);
        return !string.IsNullOrEmpty(ext) && DangerousContainerExtensions.Contains(ext);
    }

    public static LnkAnalysisResult AnalyzeLnkFile(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return new LnkAnalysisResult(false, false, 0, string.Empty, Array.Empty<string>());
        }

        try
        {
            var info = new FileInfo(filePath);
            if (info.Length < 76)
            {
                return new LnkAnalysisResult(false, false, 0, string.Empty, Array.Empty<string>());
            }

            int toRead = (int)Math.Min(256 * 1024, info.Length);
            var bytes = new byte[toRead];
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                int read = fs.Read(bytes, 0, toRead);
                return AnalyzeLnkBytes(bytes.AsSpan(0, read), info.Length, Path.GetFileName(filePath));
            }
        }
        catch
        {
            return new LnkAnalysisResult(false, false, 0, string.Empty, Array.Empty<string>());
        }
    }

    public static LnkAnalysisResult AnalyzeLnkBytes(ReadOnlySpan<byte> data, long totalFileSize, string fileName = "")
    {
        // Shell Link Header size is always 0x0000004C (76 bytes)
        if (data.Length < 76 || BinaryPrimitives.ReadUInt32LittleEndian(data[..4]) != 0x0000004C)
        {
            return new LnkAnalysisResult(false, false, 0, string.Empty, Array.Empty<string>());
        }

        var extractedText = ExtractPrintableAsciiAndUnicode(data);
        var reasons = new List<string>();
        int score = 0;

        // 1. Check if LNK invokes cmd / powershell / mshta / wscript / certutil / findstr (Kimsuky #1 technique)
        var matchedTargets = SuspiciousLnkTargets
            .Where(t => extractedText.Contains(t, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (LnkBoundaryFlagsRegex.IsMatch(extractedText))
        {
            matchedTargets.Add("iex/-enc");
        }

        // Official WSLg (Windows Subsystem for Linux GUI) Start Menu shortcuts target System32\wslg.exe
        // and often store distro icons under AppData\Local\Temp; do not false-trigger when no shell/script engine is present.
        bool isBenignWslgIconOnly =
            extractedText.Contains("wslg.exe", StringComparison.OrdinalIgnoreCase) &&
            matchedTargets.Count > 0 &&
            matchedTargets.All(t => t.Equals("AppData\\Local\\Temp", StringComparison.OrdinalIgnoreCase));

        if (matchedTargets.Count > 0 && !isBenignWslgIconOnly)
        {
            score += 75;
            reasons.Add($"LNK 바로가기가 셸/스크립트 엔진 호출 ({string.Join(", ", matchedTargets.Take(4))})");
        }
        else if (extractedText.Contains("ProgramData\\", StringComparison.OrdinalIgnoreCase))
        {
            score += 25;
        }

        // 2. Check for Kimsuky whitespace padding trick (hiding arguments off-screen in Properties dialog)
        if (WhitespacePaddingRegex.IsMatch(extractedText))
        {
            score += 45;
            reasons.Add("LNK 인자 숨김용 대량 공백 패딩(김수키 스피어피싱 기법) 탐지");
        }

        // 3. Check for oversized LNK (> 32 KB indicates appended decoy HWP/PDF + carved payload stub)
        if (totalFileSize >= 32 * 1024)
        {
            score += 40;
            reasons.Add($"비정상 대용량 LNK ({totalFileSize / 1024} KB — 미끼 문서/페이로드 오버레이 결합 의심)");
        }

        // 4. Double extension LNK (e.g. 세금계산서.pdf.lnk, 이력서.hwp.lnk)
        if (fileName.Contains(".pdf.", StringComparison.OrdinalIgnoreCase) ||
            fileName.Contains(".hwp.", StringComparison.OrdinalIgnoreCase) ||
            fileName.Contains(".hwpx.", StringComparison.OrdinalIgnoreCase) ||
            fileName.Contains(".doc.", StringComparison.OrdinalIgnoreCase) ||
            fileName.Contains(".docx.", StringComparison.OrdinalIgnoreCase) ||
            fileName.Contains(".xls.", StringComparison.OrdinalIgnoreCase) ||
            fileName.Contains(".xlsx.", StringComparison.OrdinalIgnoreCase) ||
            fileName.Contains(".jpg.", StringComparison.OrdinalIgnoreCase))
        {
            score += 40;
            reasons.Add($"문서 위장 이중 확장자 바로가기 ({fileName})");
        }

        score = Math.Clamp(score, 0, 100);
        var snippet = extractedText.Length > 240 ? extractedText[..240] : extractedText;
        return new LnkAnalysisResult(
            IsLnkFile: true,
            IsMaliciousOrSuspicious: score >= 50,
            RiskScore: score,
            ExtractedCommand: snippet.Trim(),
            Reasons: reasons);
    }

    private static string ExtractPrintableAsciiAndUnicode(ReadOnlySpan<byte> data)
    {
        var sb = new StringBuilder();

        // Extract UTF-16LE runs at BOTH even (0) and odd (1) byte parities!
        // MS-SHLLINK LinkTargetIDList / LinkInfo frequently have odd byte lengths, shifting StringData to odd offsets.
        for (int parity = 0; parity <= 1; parity++)
        {
            int uStart = -1;
            int uChars = 0;
            for (int i = parity; i + 1 < data.Length; i += 2)
            {
                byte lo = data[i];
                byte hi = data[i + 1];
                if (hi == 0 && lo >= 32 && lo <= 126)
                {
                    if (uStart < 0) uStart = i;
                    uChars++;
                }
                else
                {
                    if (uChars >= 4)
                    {
                        sb.Append(Encoding.Unicode.GetString(data.Slice(uStart, uChars * 2))).Append(' ');
                    }
                    uStart = -1;
                    uChars = 0;
                }
            }
            if (uChars >= 4 && uStart >= 0)
            {
                sb.Append(Encoding.Unicode.GetString(data.Slice(uStart, uChars * 2))).Append(' ');
            }
        }

        // Also extract ASCII runs
        int aStart = -1;
        int aChars = 0;
        for (int i = 0; i < data.Length; i++)
        {
            byte b = data[i];
            if (b >= 32 && b <= 126)
            {
                if (aStart < 0) aStart = i;
                aChars++;
            }
            else
            {
                if (aChars >= 5)
                {
                    sb.Append(Encoding.ASCII.GetString(data.Slice(aStart, aChars))).Append(' ');
                }
                aStart = -1;
                aChars = 0;
            }
        }
        if (aChars >= 5 && aStart >= 0)
        {
            sb.Append(Encoding.ASCII.GetString(data.Slice(aStart, aChars)));
        }

        return sb.ToString();
    }
}
