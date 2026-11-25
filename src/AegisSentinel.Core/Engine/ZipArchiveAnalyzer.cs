using System.IO.Compression;
using System.Text;
using AegisSentinel.Core.Models;

namespace AegisSentinel.Core.Engine;

public sealed record ZipInspectionResult(
    bool IsValidZip,
    bool IsMaliciousOrSuspicious,
    int RiskScore,
    IReadOnlyList<string> Reasons);

/// <summary>
/// Pure in-memory .ZIP archive threat inspector (never extracts untrusted files to disk).
/// Catches North Korean APT and modern phishing delivery archives containing disguised .LNK shortcuts,
/// double-extension executables (.pdf.exe / .hwp.lnk), malicious scripts (.vbs/.js/.ps1/.hta/.bat),
/// spear-phishing disk containers (.iso/.vhd/.chm), or packed RWX PE binaries.
/// </summary>
public static class ZipArchiveAnalyzer
{
    private const int MaxEntriesToInspect = 2500;
    private const int MaxDecompressedEntries = 64;
    private const long MaxSingleEntryBytes = 1024 * 1024; // 1 MB zip-bomb cap per entry

    internal static readonly string[] DisguisedDocMarkers =
    {
        ".pdf.", ".hwp.", ".hwpx.", ".doc.", ".docx.", ".xls.", ".xlsx.", ".ppt.", ".pptx.", ".jpg.", ".jpeg.", ".png."
    };

    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".scr", ".com", ".dll", ".msi", ".pif", ".cpl", ".xll", ".ocx"
    };

    public static ZipInspectionResult AnalyzeZipFile(string zipPath, GuardPolicy policy)
    {
        if (string.IsNullOrWhiteSpace(zipPath) || !File.Exists(zipPath))
        {
            return new ZipInspectionResult(false, false, 0, Array.Empty<string>());
        }

        try
        {
            using var fs = new FileStream(zipPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var archive = new ZipArchive(fs, ZipArchiveMode.Read, leaveOpen: false);

            int maxScore = 0;
            var reasons = new List<string>();
            int inspected = 0;
            int decompressed = 0;

            foreach (var entry in archive.Entries)
            {
                if (inspected >= MaxEntriesToInspect) break;
                if (string.IsNullOrEmpty(entry.Name)) continue; // Directory entry
                inspected++;

                var entryName = entry.Name;
                var ext = Path.GetExtension(entryName);
                if (string.IsNullOrWhiteSpace(ext)) continue;

                // 1. Double-extension masquerading inside archive (e.g. 세금계산서.pdf.exe, 이력서.hwp.lnk)
                if (DisguisedDocMarkers.Any(m => entryName.Contains(m, StringComparison.OrdinalIgnoreCase)) &&
                    (ExecutableExtensions.Contains(ext) ||
                     ScriptFileAnalyzer.IsSupportedScriptExtension(ext) ||
                     ext.Equals(".lnk", StringComparison.OrdinalIgnoreCase)))
                {
                    maxScore = Math.Max(maxScore, 90);
                    reasons.Add($"ZIP 내부 문서 위장 이중확장자 파일: '{entryName}'");
                }

                // 2. Spear-phishing container (.iso/.vhd/.chm) nested inside ZIP
                if (LnkAndContainerAnalyzer.IsSpearPhishingContainer(entryName))
                {
                    maxScore = Math.Max(maxScore, ext.Equals(".chm", StringComparison.OrdinalIgnoreCase) ? 80 : 70);
                    reasons.Add($"ZIP 내부 스피어피싱 고위험 컨테이너({ext}): '{entryName}'");
                    continue;
                }

                // 3. In-memory .LNK shortcut binary analysis (Kimsuky #1 ZIP->LNK delivery vector!)
                if (ext.Equals(".lnk", StringComparison.OrdinalIgnoreCase))
                {
                    if (decompressed < MaxDecompressedEntries)
                    {
                        decompressed++;
                        var bytes = ReadEntryBytesSafe(entry, maxBytes: 256 * 1024);
                        var lnk = LnkAndContainerAnalyzer.AnalyzeLnkBytes(bytes, entry.Length, entryName);
                        if (lnk.IsMaliciousOrSuspicious)
                        {
                            maxScore = Math.Max(maxScore, Math.Max(85, lnk.RiskScore));
                            reasons.Add($"ZIP 내부 악성 LNK 바로가기('{entryName}'): {string.Join(", ", lnk.Reasons)}");
                            continue;
                        }
                    }

                    // Clean .lnk inside ZIP (e.g. portable utility bundle): flag at low-medium 45 instead of auto-quarantine 60
                    maxScore = Math.Max(maxScore, 45);
                    reasons.Add($"ZIP 내부 바로가기(.lnk) 파일 포함: '{entryName}'");
                    continue;
                }

                // 4. In-memory script content analysis (.ps1, .bat, .cmd, .vbs, .js, .hta, .wsf, .sct — UTF-8 & UTF-16LE aware)
                if (ScriptFileAnalyzer.IsSupportedScriptExtension(ext))
                {
                    if (decompressed < MaxDecompressedEntries)
                    {
                        decompressed++;
                        var bytes = ReadEntryBytesSafe(entry, maxBytes: 128 * 1024);
                        if (bytes.Length > 0)
                        {
                            var sigHit = SignaturePatternScanner.ScanBytes(bytes, isSigned: false, ext);
                            if (sigHit.IsMatched)
                            {
                                maxScore = Math.Max(maxScore, sigHit.RiskScore);
                                reasons.Add($"ZIP 내부 시그니처 탐지('{entryName}'): [{sigHit.ThreatName}] {sigHit.Reason}");
                            }

                            var text = ScriptFileAnalyzer.DecodeScriptBytes(bytes);
                            var scriptRes = ScriptFileAnalyzer.AnalyzeScriptContent(text, ext, policy);
                            if (scriptRes.IsSuspicious)
                            {
                                maxScore = Math.Max(maxScore, scriptRes.RiskScore);
                                reasons.Add($"ZIP 내부 악성 스크립트('{entryName}'): {string.Join(", ", scriptRes.Reasons)}");
                            }
                        }
                    }
                    continue;
                }

                // 5. In-memory PE static analysis + YARA/EICAR signature scan for executables inside ZIP
                if (ExecutableExtensions.Contains(ext))
                {
                    if (decompressed < MaxDecompressedEntries)
                    {
                        decompressed++;
                        var bytes = ReadEntryBytesSafe(entry, maxBytes: (int)MaxSingleEntryBytes);
                        if (bytes.Length > 0)
                        {
                            var sigHit = SignaturePatternScanner.ScanBytes(bytes, isSigned: false, ext);
                            if (sigHit.IsMatched)
                            {
                                maxScore = Math.Max(maxScore, sigHit.RiskScore);
                                reasons.Add($"ZIP 내부 악성 시그니처('{entryName}'): [{sigHit.ThreatName}] {sigHit.Reason}");
                            }

                            if (bytes.Length >= 64)
                            {
                                var pe = PeStaticAnalyzer.AnalyzeBytes(bytes);
                                if (pe.IsValidPe && pe.HeuristicScore >= 60)
                                {
                                    maxScore = Math.Max(maxScore, Math.Min(95, pe.HeuristicScore + 15));
                                    reasons.Add($"ZIP 내부 패커/인젝션 의심 실행파일('{entryName}'): {pe.Summary}");
                                }
                            }
                        }
                    }
                    continue;
                }

                // 6. EICAR test file inside ZIP (e.g. eicar_com.zip -> eicar.com / eicar.txt)
                if (decompressed < MaxDecompressedEntries &&
                    entry.Length > 0 && entry.Length <= 128 &&
                    (ext.Equals(".txt", StringComparison.OrdinalIgnoreCase) ||
                     ext.Equals(".bin", StringComparison.OrdinalIgnoreCase) ||
                     ext.Equals(".dat", StringComparison.OrdinalIgnoreCase)))
                {
                    decompressed++;
                    var bytes = ReadEntryBytesSafe(entry, maxBytes: 128);
                    var sigHit = SignaturePatternScanner.ScanBytes(bytes, isSigned: false, ext);
                    if (sigHit.IsMatched)
                    {
                        maxScore = Math.Max(maxScore, sigHit.RiskScore);
                        reasons.Add($"ZIP 내부 테스트/악성 시그니처('{entryName}'): [{sigHit.ThreatName}] {sigHit.Reason}");
                    }
                }
            }

            maxScore = Math.Clamp(maxScore, 0, 100);
            return new ZipInspectionResult(true, maxScore >= 55, maxScore, reasons);
        }
        catch
        {
            return new ZipInspectionResult(false, false, 0, Array.Empty<string>());
        }
    }

    private static byte[] ReadEntryBytesSafe(ZipArchiveEntry entry, int maxBytes)
    {
        try
        {
            using var stream = entry.Open();
            using var ms = new MemoryStream();
            var buffer = new byte[16384];
            int total = 0;
            int read;
            while (total < maxBytes && (read = stream.Read(buffer, 0, Math.Min(buffer.Length, maxBytes - total))) > 0)
            {
                ms.Write(buffer, 0, read);
                total += read;
            }
            return ms.ToArray();
        }
        catch
        {
            return Array.Empty<byte>();
        }
    }
}
