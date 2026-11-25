using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using AegisSentinel.Core.Models;

namespace AegisSentinel.Core.Engine;

public enum SignatureMagicFilter
{
    Any,
    PeOnly,         // uint16(0) == 0x5A4D ("MZ")
    ScriptOrText,   // Non-PE text/script extensions
    OfficeContainer // OLE2 (D0 CF 11 E0) or OOXML/ZIP (50 4B 03 04)
}

public sealed record SignatureMatchResult(
    bool IsMatched,
    string ThreatName,
    int RiskScore,
    ThreatSeverity Severity,
    string Reason);

/// <summary>
/// YARA-X-inspired multi-indicator virus/malware/shellcode/supply-chain/macro signature engine:
///   1) Cheap short-circuit order: filesize -> magic bytes -> precompiled hex wildcards -> multi-category strings
///   2) Full-file scanning up to 12 MB (zero middle-of-binary blind spot on Go/Rust/C++ malware)
///   3) In-memory OOXML vbaProject.bin decompression for Office macro droppers
///   4) Zero untrusted raw-string vendor exclusions (cannot be bypassed by embedding "Google Chrome" / "Microsoft")
///   5) Canonical EICAR hash verification (including optional trailing whitespace per EICAR spec)
/// </summary>
public static class SignaturePatternScanner
{
    private const long FullScanCeilingBytes = 12 * 1024 * 1024; // Read entire unsigned binary up to 12 MB

    private static readonly HashSet<string> EicarSha256Hashes = new(StringComparer.OrdinalIgnoreCase)
    {
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", // 68-byte standard EICAR
        "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267", // EICAR + CRLF
        "9a120a2e38832c2d9a399853b82d1b2c780422437645053564844028496c1421"  // EICAR + LF
    };

    private static readonly HashSet<string> InspectableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".com", ".sys", ".ocx", ".msi", ".bin", ".cpl", ".pif", ".xll",
        ".ps1", ".bat", ".cmd", ".vbs", ".js", ".mjs", ".cjs", ".jse", ".vbe", ".hta", ".wsf", ".sct",
        ".doc", ".docm", ".xls", ".xlsm", ".pptm", ".rtf",
        ".txt", ".json", ".cfg", ".conf", ".ini", ".xml", ".py"
    };

    private sealed record YaraStyleRule(
        string ThreatName,
        int RiskScore,
        ThreatSeverity Severity,
        string Description,
        bool RequireUnsigned,
        long MaxFileSizeBytes,
        SignatureMagicFilter MagicFilter,
        string[] RequiredTokens,
        string[] OptionalAnyTokens,
        int MinOptionalMatches,
        short[]? CompiledHexPattern = null,
        bool ScanNonMicrosoftSigned = false);

    private static readonly YaraStyleRule[] Rules =
    {
        new(
            ThreatName: "Shellcode.Win64.ApiHashPrologue",
            RiskScore: 98,
            Severity: ThreatSeverity.Critical,
            Description: "x64 포지션 독립 셸코드(Reflective/API-Hash 스택 정렬 프롤로그) 바이트 패턴 탐지",
            RequireUnsigned: true,
            MaxFileSizeBytes: 5 * 1024 * 1024,
            MagicFilter: SignatureMagicFilter.Any,
            RequiredTokens: Array.Empty<string>(),
            OptionalAnyTokens: Array.Empty<string>(),
            MinOptionalMatches: 0,
            CompiledHexPattern: CompileHexWildcard("FC 48 83 E4 F0 E8 ?? ?? ?? ?? 41 51"),
            ScanNonMicrosoftSigned: true),
        new(
            ThreatName: "Miner.Multi.CryptoMiner",
            RiskScore: 95,
            Severity: ThreatSeverity.Critical,
            Description: "암호화폐 채굴기(CoinMiner / Stratum 풀 통신) 시그니처 탐지",
            RequireUnsigned: true,
            MaxFileSizeBytes: 25 * 1024 * 1024,
            MagicFilter: SignatureMagicFilter.Any,
            RequiredTokens: new[] { string.Concat("stra", "tum+") },
            OptionalAnyTokens: new[]
            {
                string.Concat("ran", "domx"),
                string.Concat("crypto", "night"),
                string.Concat("xm", "rig"),
                string.Concat("mining.", "subscribe"),
                string.Concat("donate-", "level"),
                string.Concat("mon", "ero")
            },
            MinOptionalMatches: 1,
            ScanNonMicrosoftSigned: true),
        new(
            ThreatName: "Trojan.Win32.BrowserStealer",
            RiskScore: 90,
            Severity: ThreatSeverity.Critical,
            Description: "브라우저 자격증명/쿠키 탈취 및 외부 웹훅 유출 스틸러 시그니처 탐지",
            RequireUnsigned: true,
            MaxFileSizeBytes: 20 * 1024 * 1024,
            MagicFilter: SignatureMagicFilter.Any,
            RequiredTokens: new[] { string.Concat("Login ", "Data"), string.Concat("Local ", "State") },
            OptionalAnyTokens: new[]
            {
                string.Concat("CryptUn", "protectData"),
                string.Concat("os_", "crypt"),
                string.Concat("encrypted_", "key"),
                string.Concat("discord.com", "/api/webhooks"),
                string.Concat("api.telegram", ".org/bot")
            },
            MinOptionalMatches: 2,
            ScanNonMicrosoftSigned: true),
        new(
            ThreatName: "Backdoor.Multi.ReverseShell",
            RiskScore: 90,
            Severity: ThreatSeverity.Critical,
            Description: "원격 리버스 셸(Reverse Shell) 백도어 페이로드 시그니처 탐지",
            RequireUnsigned: true,
            MaxFileSizeBytes: 12 * 1024 * 1024,
            MagicFilter: SignatureMagicFilter.Any,
            RequiredTokens: new[] { string.Concat("TCP", "Client"), string.Concat("Get", "Stream") },
            OptionalAnyTokens: new[]
            {
                string.Concat("cmd", ".exe"),
                string.Concat("power", "shell"),
                string.Concat("Invoke-", "Expression"),
                string.Concat("RedirectStandard", "Input"),
                string.Concat("Start-", "Process")
            },
            MinOptionalMatches: 2),
        new(
            ThreatName: "Ransom.Win32.ShadowWiper",
            RiskScore: 95,
            Severity: ThreatSeverity.Critical,
            Description: "랜섬웨어 복구 무력화(섀도 복사본 삭제 + 협박문/암호화 루틴) 시그니처 탐지",
            RequireUnsigned: true,
            MaxFileSizeBytes: 15 * 1024 * 1024,
            MagicFilter: SignatureMagicFilter.Any,
            RequiredTokens: new[] { string.Concat("delete ", "shadows") },
            OptionalAnyTokens: new[]
            {
                string.Concat("recovery", "enabled no"),
                string.Concat("wbadmin ", "delete"),
                string.Concat("Your files ", "have been encrypted"),
                string.Concat("decrypt_", "instructions"),
                string.Concat("bit", "coin"),
                string.Concat("tor", "project")
            },
            MinOptionalMatches: 1,
            ScanNonMicrosoftSigned: true),
        new(
            ThreatName: "PUA.Win32.BrowserHijacker",
            RiskScore: 80,
            Severity: ThreatSeverity.High,
            Description: "브라우저 강제 확장프로그램/시작페이지 변조 애드웨어(PUA) 시그니처 탐지",
            RequireUnsigned: true,
            MaxFileSizeBytes: 20 * 1024 * 1024,
            MagicFilter: SignatureMagicFilter.Any,
            RequiredTokens: new[] { string.Concat("ExtensionInstall", "Forcelist") },
            OptionalAnyTokens: new[]
            {
                string.Concat("Homepage", "Location"),
                string.Concat("RestoreOn", "StartupURLs"),
                string.Concat("NewTabPage", "Location"),
                string.Concat("clients2.google.com", "/service/update2/crx")
            },
            MinOptionalMatches: 1),
        new(
            ThreatName: "Trojan.Win32.CredDumperArtifact",
            RiskScore: 95,
            Severity: ThreatSeverity.Critical,
            Description: "자격증명 메모리 덤프(LSASS / MiniDump / WDigest) 악성 도구 시그니처 탐지",
            RequireUnsigned: true,
            MaxFileSizeBytes: 15 * 1024 * 1024,
            MagicFilter: SignatureMagicFilter.Any,
            RequiredTokens: new[] { string.Concat("ls", "ass") },
            OptionalAnyTokens: new[]
            {
                string.Concat("MiniDump", "WriteDump"),
                string.Concat("sekur", "lsa"),
                string.Concat("logon", "passwords"),
                string.Concat("UseLogon", "Credential"),
                string.Concat("comsvcs", ".dll")
            },
            MinOptionalMatches: 2,
            ScanNonMicrosoftSigned: true),
        new(
            ThreatName: "SupplyChain.JS.ObfuscatedCredExfil",
            RiskScore: 88,
            Severity: ThreatSeverity.Critical,
            Description: "난독화 JavaScript/npm 공급망 자격증명 탈취(env/.ssh/.npmrc + 외부 웹훅 유출) 탐지",
            RequireUnsigned: true,
            MaxFileSizeBytes: 2 * 1024 * 1024,
            MagicFilter: SignatureMagicFilter.ScriptOrText,
            RequiredTokens: new[] { string.Concat("eval", "(") },
            OptionalAnyTokens: new[]
            {
                string.Concat("fromChar", "Code"),
                string.Concat(".ssh/", "id_rsa"),
                string.Concat(".npm", "rc"),
                string.Concat("discord.com", "/api/webhooks"),
                string.Concat("api.telegram", ".org/bot")
            },
            MinOptionalMatches: 3),
        new(
            ThreatName: "Macro.Office.AutoExecShellDropper",
            RiskScore: 92,
            Severity: ThreatSeverity.Critical,
            Description: "오피스 문서 자동 실행 매크로(AutoOpen/Document_Open) + 셸 드로퍼 시그니처 탐지",
            RequireUnsigned: true,
            MaxFileSizeBytes: 15 * 1024 * 1024,
            MagicFilter: SignatureMagicFilter.OfficeContainer,
            RequiredTokens: new[] { string.Concat("WScript.", "Shell") },
            OptionalAnyTokens: new[]
            {
                string.Concat("Auto", "Open"),
                string.Concat("Document_", "Open"),
                string.Concat("Workbook_", "Open"),
                string.Concat("power", "shell"),
                string.Concat("URLDownload", "ToFile")
            },
            MinOptionalMatches: 2)
    };

    public static SignatureMatchResult ScanFile(string filePath, SignatureInfo signature, string? precomputedSha256 = null)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return new SignatureMatchResult(false, string.Empty, 0, ThreatSeverity.Info, string.Empty);
        }

        try
        {
            var info = new FileInfo(filePath);
            if (info.Length == 0)
            {
                return new SignatureMatchResult(false, string.Empty, 0, ThreatSeverity.Info, string.Empty);
            }

            // 1. Canonical EICAR test file detection (filesize <= 128 including optional trailing spaces/tabs/CR/LF)
            if (info.Length <= 128)
            {
                if (!string.IsNullOrWhiteSpace(precomputedSha256) && EicarSha256Hashes.Contains(precomputedSha256))
                {
                    return EicarHit();
                }
                var smallBytes = ReadFullBounded(filePath, (int)info.Length);
                if (IsEicarBytes(smallBytes))
                {
                    return EicarHit();
                }
            }

            var ext = Path.GetExtension(filePath);
            if (!InspectableExtensions.Contains(ext))
            {
                return new SignatureMatchResult(false, string.Empty, 0, ThreatSeverity.Info, string.Empty);
            }

            // Stolen-certificate / compromised-vendor supply-chain defense:
            // Only TrustedMicrosoft skips YARA; 3rd-party TrustedVendor binaries up to 12 MB are STILL scanned
            // against high-confidence malware rules (shellcode, browser stealer, shadow wiper, LSASS dumper, miner)!
            if (info.Length > 25 * 1024 * 1024 ||
                signature.Status == SignatureStatus.TrustedMicrosoft ||
                (signature.IsSigned && info.Length > FullScanCeilingBytes))
            {
                return new SignatureMatchResult(false, string.Empty, 0, ThreatSeverity.Info, string.Empty);
            }

            var rawSample = ReadSampleBytes(filePath, info.Length);
            if (rawSample.Length == 0)
            {
                return new SignatureMatchResult(false, string.Empty, 0, ThreatSeverity.Info, string.Empty);
            }

            return EvaluateSample(rawSample, info.Length, signature.IsSigned, signature.Status == SignatureStatus.TrustedMicrosoft, ext);
        }
        catch
        {
            return new SignatureMatchResult(false, string.Empty, 0, ThreatSeverity.Info, string.Empty);
        }
    }

    public static SignatureMatchResult ScanBytes(ReadOnlySpan<byte> data, bool isSigned, string extension = ".exe", bool isMicrosoftSigned = false)
    {
        if (data.Length == 0)
        {
            return new SignatureMatchResult(false, string.Empty, 0, ThreatSeverity.Info, string.Empty);
        }

        if (data.Length <= 128 && IsEicarBytes(data))
        {
            return EicarHit();
        }

        return EvaluateSample(data, data.Length, isSigned, isMicrosoftSigned, extension);
    }

    public static bool MatchHexWildcardPattern(ReadOnlySpan<byte> haystack, string hexPattern)
    {
        var compiled = CompileHexWildcard(hexPattern);
        return compiled is not null && MatchCompiledHex(haystack, compiled);
    }

    private static short[]? CompileHexWildcard(string hexPattern)
    {
        if (string.IsNullOrWhiteSpace(hexPattern)) return null;
        var tokens = hexPattern.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length == 0) return null;
        var arr = new short[tokens.Length];
        for (int i = 0; i < tokens.Length; i++)
        {
            if (tokens[i] == "??" || tokens[i] == "?") arr[i] = -1;
            else if (byte.TryParse(tokens[i], System.Globalization.NumberStyles.HexNumber, null, out byte b)) arr[i] = b;
            else return null;
        }
        return arr;
    }

    private static bool MatchCompiledHex(ReadOnlySpan<byte> haystack, short[] pattern)
    {
        if (pattern.Length == 0 || pattern.Length > haystack.Length) return false;
        int maxStart = haystack.Length - pattern.Length;
        short first = pattern[0];
        for (int i = 0; i <= maxStart; i++)
        {
            if (first >= 0 && haystack[i] != first) continue;
            bool matched = true;
            for (int j = 1; j < pattern.Length; j++)
            {
                short expected = pattern[j];
                if (expected >= 0 && haystack[i + j] != expected)
                {
                    matched = false;
                    break;
                }
            }
            if (matched) return true;
        }
        return false;
    }

    private static SignatureMatchResult EvaluateSample(ReadOnlySpan<byte> rawBytes, long totalFileSize, bool isSigned, bool isMicrosoftSigned, string ext)
    {
        bool isPeMagic = rawBytes.Length >= 2 && BinaryPrimitives.ReadUInt16LittleEndian(rawBytes[..2]) == 0x5A4D;
        bool isPkZipMagic = rawBytes.Length >= 4 && BinaryPrimitives.ReadUInt32LittleEndian(rawBytes[..4]) == 0x04034B50;
        bool isOle2Magic = rawBytes.Length >= 4 && BinaryPrimitives.ReadUInt32LittleEndian(rawBytes[..4]) == 0xE011CFD0;
        bool isOfficeMagic = isPkZipMagic || isOle2Magic;

        bool isConfigOrText = ext.Equals(".txt", StringComparison.OrdinalIgnoreCase) ||
                              ext.Equals(".json", StringComparison.OrdinalIgnoreCase) ||
                              ext.Equals(".cfg", StringComparison.OrdinalIgnoreCase) ||
                              ext.Equals(".conf", StringComparison.OrdinalIgnoreCase) ||
                              ext.Equals(".ini", StringComparison.OrdinalIgnoreCase) ||
                              ext.Equals(".xml", StringComparison.OrdinalIgnoreCase);

        string? lazyPrintable = null;
        string? lazyOoxmlMacroPrintable = null;

        foreach (var rule in Rules)
        {
            if (isMicrosoftSigned && rule.RequireUnsigned) continue;
            if (isSigned && rule.RequireUnsigned && !rule.ScanNonMicrosoftSigned) continue;
            if (totalFileSize > rule.MaxFileSizeBytes) continue;

            if (rule.MagicFilter == SignatureMagicFilter.PeOnly && !isPeMagic) continue;
            if (rule.MagicFilter == SignatureMagicFilter.OfficeContainer && !isOfficeMagic) continue;
            if (rule.MagicFilter == SignatureMagicFilter.ScriptOrText && isPeMagic) continue;

            if (isConfigOrText && rule.ThreatName != "Miner.Multi.CryptoMiner")
            {
                continue;
            }

            if (rule.CompiledHexPattern is not null)
            {
                if (!MatchCompiledHex(rawBytes, rule.CompiledHexPattern))
                {
                    continue;
                }
                if (rule.RequiredTokens.Length == 0 && rule.MinOptionalMatches == 0)
                {
                    return new SignatureMatchResult(true, rule.ThreatName, rule.RiskScore, rule.Severity, rule.Description);
                }
            }

            // For OOXML Office containers (.docm/.xlsm/.pptm), decompress vbaProject.bin in memory so macro tokens are visible!
            string textToSearch;
            if (rule.MagicFilter == SignatureMagicFilter.OfficeContainer && isPkZipMagic)
            {
                lazyOoxmlMacroPrintable ??= ExtractOoxmlMacroText(rawBytes);
                textToSearch = lazyOoxmlMacroPrintable;
            }
            else
            {
                lazyPrintable ??= ExtractPrintableText(rawBytes);
                textToSearch = lazyPrintable;
            }

            if (string.IsNullOrEmpty(textToSearch)) continue;

            bool allRequired = true;
            foreach (var req in rule.RequiredTokens)
            {
                if (!textToSearch.Contains(req, StringComparison.OrdinalIgnoreCase))
                {
                    allRequired = false;
                    break;
                }
            }
            if (!allRequired) continue;

            int optMatches = 0;
            foreach (var opt in rule.OptionalAnyTokens)
            {
                if (textToSearch.Contains(opt, StringComparison.OrdinalIgnoreCase))
                {
                    optMatches++;
                    if (optMatches >= rule.MinOptionalMatches) break;
                }
            }

            if (optMatches >= rule.MinOptionalMatches)
            {
                // Legitimate 3rd-party signed browsers / password managers (1Password, Bitwarden, Brave, Whale) reference
                // "Login Data", "Local State", and "CryptUnprotectData" for local profile import.
                // On validly signed binaries, require an explicit Discord/Telegram exfiltration webhook before convicting!
                if (isSigned && rule.ThreatName == "Trojan.Win32.BrowserStealer")
                {
                    bool hasWebhookExfil =
                        textToSearch.Contains(string.Concat("discord.com", "/api/webhooks"), StringComparison.OrdinalIgnoreCase) ||
                        textToSearch.Contains(string.Concat("api.telegram", ".org/bot"), StringComparison.OrdinalIgnoreCase);
                    if (!hasWebhookExfil)
                    {
                        continue;
                    }
                }

                return new SignatureMatchResult(true, rule.ThreatName, rule.RiskScore, rule.Severity, rule.Description);
            }
        }

        return new SignatureMatchResult(false, string.Empty, 0, ThreatSeverity.Info, string.Empty);
    }

    private static string ExtractOoxmlMacroText(ReadOnlySpan<byte> zipBytes)
    {
        try
        {
            using var ms = new MemoryStream(zipBytes.ToArray(), writable: false);
            using var archive = new ZipArchive(ms, ZipArchiveMode.Read);
            var sb = new StringBuilder();
            foreach (var entry in archive.Entries)
            {
                var name = entry.FullName;
                if (!name.Contains("vbaProject", StringComparison.OrdinalIgnoreCase) &&
                    !name.Contains("externalLink", StringComparison.OrdinalIgnoreCase) &&
                    !name.EndsWith(".rels", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                if (entry.Length <= 0 || entry.Length > 4 * 1024 * 1024) continue;
                using var s = entry.Open();
                using var mem = new MemoryStream();
                s.CopyTo(mem);
                sb.Append('\n');
                sb.Append(ExtractPrintableText(mem.GetBuffer().AsSpan(0, (int)mem.Length)));
            }
            return sb.ToString();
        }
        catch
        {
            return ExtractPrintableText(zipBytes);
        }
    }

    private static bool IsEicarBytes(ReadOnlySpan<byte> data)
    {
        if (data.Length < 68 || data.Length > 128) return false;
        // Trim optional trailing spaces/tabs/CR/LF allowed by the official EICAR specification
        int end = data.Length;
        while (end > 68 && data[end - 1] is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n')
        {
            end--;
        }
        if (end != 68) return false;
        var sha = Convert.ToHexString(SHA256.HashData(data[..68]));
        return EicarSha256Hashes.Contains(sha);
    }

    private static SignatureMatchResult EicarHit() => new(
        true,
        "EICAR-Standard-AntiVirus-Test",
        100,
        ThreatSeverity.Critical,
        "국제 표준 백신 테스트 파일(EICAR) 시그니처 일치 — 정상 탐지 검증");

    private static byte[] ReadFullBounded(string filePath, int length)
    {
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var buf = new byte[length];
        int total = 0;
        while (total < length)
        {
            int r = fs.Read(buf, total, length - total);
            if (r <= 0) break;
            total += r;
        }
        return total == length ? buf : buf[..total];
    }

    private static byte[] ReadSampleBytes(string filePath, long fileLen)
    {
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        // Full scan up to 12 MB so payloads/strings in the middle of Go/Rust/C++ binaries are NEVER missed!
        if (fileLen <= FullScanCeilingBytes)
        {
            int len = (int)fileLen;
            var full = new byte[len];
            int total = 0;
            while (total < len)
            {
                int r = fs.Read(full, total, len - total);
                if (r <= 0) break;
                total += r;
            }
            return total == len ? full : full[..total];
        }

        // For 12 MB - 25 MB files: sample head (2 MB) + middle (1 MB) + tail (512 KB)
        const int headLen = 2 * 1024 * 1024;
        const int midLen = 1 * 1024 * 1024;
        const int tailLen = 512 * 1024;
        var buf = new byte[headLen + midLen + tailLen];
        int offset = ReadLoop(fs, buf, 0, headLen);
        fs.Seek(fileLen / 2, SeekOrigin.Begin);
        offset += ReadLoop(fs, buf, offset, midLen);
        fs.Seek(-tailLen, SeekOrigin.End);
        offset += ReadLoop(fs, buf, offset, tailLen);
        return offset == buf.Length ? buf : buf[..offset];
    }

    private static int ReadLoop(Stream fs, byte[] buf, int offset, int count)
    {
        int read = 0;
        while (read < count)
        {
            int r = fs.Read(buf, offset + read, count - read);
            if (r <= 0) break;
            read += r;
        }
        return read;
    }

    private static string ExtractPrintableText(ReadOnlySpan<byte> bytes)
    {
        var sb = new StringBuilder(bytes.Length);
        for (int i = 0; i < bytes.Length; i++)
        {
            byte b = bytes[i];
            if ((b >= 32 && b <= 126) || b is (byte)'\n' or (byte)'\r' or (byte)'\t')
            {
                sb.Append((char)b);
            }
            else if (b == 0)
            {
                // Preserve UTF-16LE wide strings (alternating ASCII + 0x00) without gluing separate ASCII C-strings
                if (i > 0 && bytes[i - 1] >= 32 && bytes[i - 1] <= 126 &&
                    i + 2 < bytes.Length && bytes[i + 1] >= 32 && bytes[i + 1] <= 126 && bytes[i + 2] == 0)
                {
                    continue;
                }
                sb.Append(' ');
            }
            else
            {
                sb.Append(' ');
            }
        }
        return sb.ToString();
    }
}
