using System.Buffers.Binary;
using System.Text;
using AegisSentinel.Core.Models;

namespace AegisSentinel.Core.Engine;

/// <summary>
/// Pure C# PE32 / PE32+ static structural and heuristic analyzer.
/// Inspects headers, RWX sections, packer section names, executable section Shannon entropy,
/// and suspicious Windows API import capability combinations without executing the binary.
/// </summary>
public static class PeStaticAnalyzer
{
    private const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
    private const uint IMAGE_SCN_MEM_WRITE = 0x80000000;

    private static readonly string[] PackerSectionPrefixes =
    {
        "UPX", ".vmp", "vmp", ".themida", ".aspack", ".adata",
        ".mpress", ".enigma", ".petite", ".nsp", ".packed", ".fsg"
    };

    private static readonly (string Name, int Weight, string Category)[] TrackedApiIndicators =
    {
        ("VirtualAllocEx", 18, "Injection"),
        ("WriteProcessMemory", 20, "Injection"),
        ("CreateRemoteThread", 22, "Injection"),
        ("QueueUserAPC", 18, "Injection"),
        ("SetThreadContext", 15, "Injection"),
        ("NtUnmapViewOfSection", 22, "Injection"),
        ("CryptUnprotectData", 16, "Credential"),
        ("MiniDumpWriteDump", 22, "Credential"),
        ("SetWindowsHookEx", 14, "Spyware"),
        ("GetAsyncKeyState", 12, "Spyware"),
        ("BCryptEncrypt", 10, "Crypto"),
        ("CryptEncrypt", 10, "Crypto"),
        ("URLDownloadToFile", 16, "Downloader"),
        ("WinHttpOpen", 8, "Network"),
        ("InternetOpenUrl", 10, "Network"),
        ("IsDebuggerPresent", 6, "AntiDebug"),
        ("CheckRemoteDebuggerPresent", 8, "AntiDebug")
    };

    public static PeAnalysisResult AnalyzeFile(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return Empty("파일 없음");
        }

        try
        {
            var info = new FileInfo(filePath);
            if (info.Length < 64)
            {
                return Empty("PE 최소 크기 미달");
            }

            // Read up to 4 MB for fast structural + section + import string analysis
            int toRead = (int)Math.Min(4 * 1024 * 1024, info.Length);
            var data = new byte[toRead];
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                int offset = 0;
                while (offset < toRead)
                {
                    int read = fs.Read(data, offset, toRead - offset);
                    if (read == 0) break;
                    offset += read;
                }
            }

            return AnalyzeBytes(data);
        }
        catch (Exception ex)
        {
            return Empty($"분석 오류: {ex.Message}");
        }
    }

    public static PeAnalysisResult AnalyzeBytes(ReadOnlySpan<byte> data)
    {
        if (data.Length < 64 || data[0] != (byte)'M' || data[1] != (byte)'Z')
        {
            return Empty("유효한 PE(MZ) 헤더 아님");
        }

        int peOffset = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0x3C, 4));
        if (peOffset < 0 || peOffset > data.Length - 24)
        {
            return Empty("잘못된 PE 오프셋");
        }

        if (data[peOffset] != (byte)'P' || data[peOffset + 1] != (byte)'E' ||
            data[peOffset + 2] != 0 || data[peOffset + 3] != 0)
        {
            return Empty("PE 시그니처 불일치");
        }

        ushort numberOfSections = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(peOffset + 6, 2));
        ushort sizeOfOptionalHeader = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(peOffset + 20, 2));

        int optOffset = peOffset + 24;
        bool is64Bit = false;
        if (optOffset >= 0 && optOffset <= data.Length - 2)
        {
            ushort optMagic = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(optOffset, 2));
            is64Bit = optMagic == 0x20B;
        }

        long sectionTableOffset = (long)optOffset + sizeOfOptionalHeader;
        var sectionNames = new List<string>();
        bool hasRwxSection = false;
        bool hasPackerName = false;
        double maxExecEntropy = 0.0;

        int maxSections = Math.Min((int)numberOfSections, 64);
        for (int i = 0; i < maxSections; i++)
        {
            long secOffsetL = sectionTableOffset + ((long)i * 40);
            if (secOffsetL < 0 || secOffsetL > data.Length - 40)
            {
                break;
            }
            int secOffset = (int)secOffsetL;

            var rawName = data.Slice(secOffset, 8);
            int nullIdx = rawName.IndexOf((byte)0);
            var secName = Encoding.ASCII.GetString(nullIdx >= 0 ? rawName[..nullIdx] : rawName).Trim();
            sectionNames.Add(secName);

            uint rawSize = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(secOffset + 16, 4));
            uint rawPtr = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(secOffset + 20, 4));
            uint characteristics = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(secOffset + 36, 4));

            bool isExec = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            bool isWrite = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;

            if (isExec && isWrite)
            {
                hasRwxSection = true;
            }

            if (PackerSectionPrefixes.Any(p => secName.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
            {
                hasPackerName = true;
            }

            if (isExec && rawSize >= 256 && rawPtr < (uint)data.Length)
            {
                int avail = (int)Math.Min(rawSize, (uint)(data.Length - (int)rawPtr));
                if (avail >= 256)
                {
                    var sample = data.Slice((int)rawPtr, Math.Min(avail, 131072));
                    double ent = EntropyAnalyzer.ComputeShannonEntropy(sample);
                    if (ent > maxExecEntropy)
                    {
                        maxExecEntropy = ent;
                    }
                }
            }
        }

        // Scan ASCII import / capability tokens across the full read buffer (up to 4 MB; Go/Rust/C++ imports often sit past 1 MB)
        var asciiText = ExtractAsciiSubset(data, maxScanBytes: data.Length);
        var apiHits = new List<string>();
        int injectionHits = 0;
        int credHits = 0;
        int spywareHits = 0;
        int apiScore = 0;

        foreach (var (name, weight, cat) in TrackedApiIndicators)
        {
            if (asciiText.Contains(name, StringComparison.Ordinal))
            {
                apiHits.Add(name);
                apiScore += weight;
                if (cat == "Injection") injectionHits++;
                else if (cat == "Credential") credHits++;
                else if (cat == "Spyware") spywareHits++;
            }
        }

        int score = 0;
        var summaryParts = new List<string>();

        if (hasPackerName)
        {
            score += 30;
            summaryParts.Add("패커/난독화 섹션 탐지");
        }

        if (hasRwxSection)
        {
            score += 25;
            summaryParts.Add("RWX(읽기·쓰기·실행) 코드 섹션");
        }

        if (maxExecEntropy >= 7.35)
        {
            score += 25;
            summaryParts.Add($"고엔트로피 코드 섹션({maxExecEntropy:F2})");
        }

        if (injectionHits >= 2)
        {
            score += 35;
            summaryParts.Add($"프로세스 인젝션 API 조합({injectionHits}종)");
        }

        if (credHits >= 1 && injectionHits >= 1)
        {
            score += 20;
            summaryParts.Add("자격증명 탈취 + 인젝션 조합");
        }

        if (spywareHits >= 2)
        {
            score += 25;
            summaryParts.Add("키로거/후킹 API 조합");
        }

        score = Math.Min(100, score + Math.Min(25, apiScore / 3));

        return new PeAnalysisResult(
            IsValidPe: true,
            Is64Bit: is64Bit,
            HasRwxSection: hasRwxSection,
            HasPackerSectionName: hasPackerName,
            MaxExecutableSectionEntropy: maxExecEntropy,
            SectionNames: sectionNames,
            SuspiciousApiHits: apiHits,
            HeuristicScore: score,
            Summary: summaryParts.Count > 0 ? string.Join(" | ", summaryParts) : "정상 PE 구조");
    }

    private static string ExtractAsciiSubset(ReadOnlySpan<byte> data, int maxScanBytes)
    {
        var sb = new StringBuilder(Math.Min(maxScanBytes / 2, 262144));
        int run = 0;
        int start = 0;

        for (int i = 0; i < maxScanBytes; i++)
        {
            byte b = data[i];
            if (b >= 32 && b <= 126)
            {
                if (run == 0) start = i;
                run++;
            }
            else
            {
                if (run >= 6 && run <= 80)
                {
                    sb.Append(Encoding.ASCII.GetString(data.Slice(start, run)));
                    sb.Append(' ');
                }
                run = 0;
            }
        }

        if (run >= 6 && run <= 80)
        {
            sb.Append(Encoding.ASCII.GetString(data.Slice(start, run)));
        }

        return sb.ToString();
    }

    private static PeAnalysisResult Empty(string reason) => new(
        IsValidPe: false,
        Is64Bit: false,
        HasRwxSection: false,
        HasPackerSectionName: false,
        MaxExecutableSectionEntropy: 0,
        SectionNames: Array.Empty<string>(),
        SuspiciousApiHits: Array.Empty<string>(),
        HeuristicScore: 0,
        Summary: reason);
}
