namespace AegisSentinel.Core.Engine;

public sealed record EntropyCheckResult(
    double ShannonEntropy,
    bool IsLikelyEncrypted,
    string Reason);

/// <summary>
/// Detects ransomware encryption with minimal false positives by combining Shannon entropy
/// with magic-header integrity checks on common office/PDF/media formats.
/// </summary>
public static class EntropyAnalyzer
{
    private static readonly HashSet<string> PlainTextExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".txt", ".csv", ".json", ".xml", ".yaml", ".yml", ".md",
        ".ini", ".cfg", ".conf", ".env", ".sql", ".cs", ".py", ".js",
        ".ts", ".html", ".css", ".cpp", ".h", ".java", ".go", ".rs", ".ps1", ".bat",
        ".pem", ".ppk"
    };

    private static readonly byte[] Ole2CompoundMagic = { 0xD0, 0xCF, 0x11, 0xE0 };

    private static readonly HashSet<string> OoxmlPasswordCapableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".docx", ".xlsx", ".pptx", ".hwpx"
    };

    private static readonly Dictionary<string, byte[]> ExpectedMagicHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        [".docx"] = new byte[] { 0x50, 0x4B, 0x03, 0x04 }, // PK ZIP header
        [".xlsx"] = new byte[] { 0x50, 0x4B, 0x03, 0x04 },
        [".pptx"] = new byte[] { 0x50, 0x4B, 0x03, 0x04 },
        [".hwpx"] = new byte[] { 0x50, 0x4B, 0x03, 0x04 }, // Hangul HWPX (ZIP-based)
        [".hwp"]  = new byte[] { 0xD0, 0xCF, 0x11, 0xE0 }, // Hangul HWP (OLE2 Compound)
        [".doc"]  = new byte[] { 0xD0, 0xCF, 0x11, 0xE0 }, // Legacy Office OLE2
        [".xls"]  = new byte[] { 0xD0, 0xCF, 0x11, 0xE0 },
        [".ppt"]  = new byte[] { 0xD0, 0xCF, 0x11, 0xE0 },
        [".pdf"]  = new byte[] { 0x25, 0x50, 0x44, 0x46 }, // %PDF
        [".png"]  = new byte[] { 0x89, 0x50, 0x4E, 0x47 },
        [".jpg"]  = new byte[] { 0xFF, 0xD8, 0xFF },
        [".jpeg"] = new byte[] { 0xFF, 0xD8, 0xFF },
        [".gif"]  = new byte[] { 0x47, 0x49, 0x46, 0x38 }
    };

    public static EntropyCheckResult AnalyzeFile(string filePath, string? extensionOverride = null)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return new EntropyCheckResult(0, false, "File not found");
        }

        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            int toRead = (int)Math.Min(65536, fs.Length);
            if (toRead < 256)
            {
                return new EntropyCheckResult(0, false, "File too small for entropy check");
            }

            var buffer = new byte[toRead];
            int bytesRead = fs.Read(buffer, 0, toRead);
            var ext = !string.IsNullOrWhiteSpace(extensionOverride) ? extensionOverride : Path.GetExtension(filePath);
            return AnalyzeBytes(buffer.AsSpan(0, bytesRead), ext);
        }
        catch (Exception ex)
        {
            return new EntropyCheckResult(0, false, ex.Message);
        }
    }

    public static EntropyCheckResult AnalyzeBytes(ReadOnlySpan<byte> data, string extension)
    {
        if (data.Length < 256)
        {
            return new EntropyCheckResult(0, false, "Insufficient sample");
        }

        double entropy = ComputeShannonEntropy(data);

        // 1. Plaintext / source code / config file suddenly turns into high-entropy ciphertext
        if (PlainTextExtensions.Contains(extension) && entropy >= 7.35)
        {
            return new EntropyCheckResult(
                entropy,
                true,
                $"평문 형식({extension}) 파일이 비정상 고엔트로피({entropy:F2} bits/byte) 암호화 데이터로 변조됨");
        }

        // 2. Office / PDF / Image file lost its valid magic header AND has ciphertext-level entropy
        // Note: Password-protected OOXML (.docx/.xlsx/.pptx/.hwpx) wraps EncryptedPackage inside an OLE2 container (D0 CF 11 E0)!
        if (ExpectedMagicHeaders.TryGetValue(extension, out var magic) && data.Length >= magic.Length)
        {
            bool headerMatches = data[..magic.Length].SequenceEqual(magic) ||
                                 (OoxmlPasswordCapableExtensions.Contains(extension) &&
                                  data.Length >= Ole2CompoundMagic.Length &&
                                  data[..Ole2CompoundMagic.Length].SequenceEqual(Ole2CompoundMagic));
            if (!headerMatches && entropy >= 7.65)
            {
                return new EntropyCheckResult(
                    entropy,
                    true,
                    $"문서/미디어({extension}) 매직 헤더가 파괴되고 암호화 엔트로피({entropy:F2})로 변조됨");
            }
        }

        return new EntropyCheckResult(entropy, false, "Normal");
    }

    public static double ComputeShannonEntropy(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return 0.0;
        }

        Span<int> counts = stackalloc int[256];
        foreach (byte b in data)
        {
            counts[b]++;
        }

        double entropy = 0.0;
        double len = data.Length;
        for (int i = 0; i < 256; i++)
        {
            if (counts[i] == 0)
            {
                continue;
            }

            double p = counts[i] / len;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }
}
