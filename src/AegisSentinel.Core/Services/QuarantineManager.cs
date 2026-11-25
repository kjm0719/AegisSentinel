using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AegisSentinel.Core.Models;

namespace AegisSentinel.Core.Services;

public sealed class QuarantineManager
{
    private static readonly byte[] LegacyMagicHeader = Encoding.ASCII.GetBytes("AEGISQ1\0");
    private static readonly byte[] AesGcmMagicHeader = Encoding.ASCII.GetBytes("AEGISQ2\0");
    private static readonly byte[] LegacyObfuscationKey =
    {
        0x5A, 0xA3, 0x19, 0xE7, 0x4C, 0x81, 0xD2, 0x3F,
        0x9B, 0x24, 0x6E, 0xC8, 0x11, 0x77, 0xF0, 0x55
    };
    private static readonly byte[] DpapiEntropy = Encoding.UTF8.GetBytes("AegisSentinel-Quarantine-AES256GCM-v7");
    private const int GcmNonceSize = 12;
    private const int GcmTagSize = 16;
    private const long MaxInMemoryGcmBytes = 64 * 1024 * 1024; // 64 MB AES-GCM authenticated ceiling

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly string _keyFilePath;
    private readonly object _keySync = new();
    private byte[]? _cachedAesKey;

    public string QuarantineDirectory { get; }

    public QuarantineManager(string? baseDirectory = null)
    {
        var root = baseDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AegisSentinel");
        QuarantineDirectory = Path.Combine(root, "Quarantine");
        Directory.CreateDirectory(QuarantineDirectory);
        _keyFilePath = Path.Combine(QuarantineDirectory, ".quarantine_aes.key");
    }

    private byte[] GetOrCreateAesKey()
    {
        lock (_keySync)
        {
            if (_cachedAesKey is not null) return _cachedAesKey;
            if (File.Exists(_keyFilePath))
            {
                var blob = File.ReadAllBytes(_keyFilePath);
                var unprotected = ProtectedData.Unprotect(blob, DpapiEntropy, DataProtectionScope.CurrentUser);
                if (unprotected.Length != 32)
                {
                    throw new CryptographicException("격리소 암호화 키 길이가 손상되었습니다.");
                }
                _cachedAesKey = unprotected;
                return _cachedAesKey;
            }

            var newKey = RandomNumberGenerator.GetBytes(32);
            var sealedBlob = ProtectedData.Protect(newKey, DpapiEntropy, DataProtectionScope.CurrentUser);
            if (File.Exists(_keyFilePath))
            {
                try { File.SetAttributes(_keyFilePath, FileAttributes.Normal); } catch { }
            }
            File.WriteAllBytes(_keyFilePath, sealedBlob);
            try { File.SetAttributes(_keyFilePath, FileAttributes.Hidden); } catch { }
            _cachedAesKey = newKey;
            return _cachedAesKey;
        }
    }

    public QuarantineEntry QuarantineFile(string originalPath, string reason)
    {
        if (!File.Exists(originalPath))
        {
            throw new FileNotFoundException("Target file does not exist.", originalPath);
        }

        originalPath = Path.GetFullPath(originalPath);
        if (IsProtectedSystemOrSelfPath(originalPath))
        {
            throw new InvalidOperationException($"시스템 핵심 파일 또는 보호된 보안/개발 환경 파일은 격리할 수 없습니다: {originalPath}");
        }

        // Sharp-Edge Defense (CVE-class AV Symlink/Reparse-Point Escape):
        // Never follow NTFS symlinks or ancestor directory junctions during elevated quarantine copy/delete.
        if (HasAnyReparsePointAncestor(originalPath))
        {
            throw new InvalidOperationException($"보안 가드레일: 상위 경로에 리파스 포인트/정션이 포함되어 임의 파일 삭제 방지를 위해 격리가 차단되었습니다: {originalPath}");
        }
        try
        {
            var attrs = File.GetAttributes(originalPath);
            if ((attrs & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidOperationException($"보안 가드레일: 심볼릭 링크/리파스 포인트({originalPath})는 임의 파일 삭제(Symlink Escape) 방지를 위해 직접 격리 대상에서 차단됩니다.");
            }
        }
        catch (InvalidOperationException) { throw; }
        catch { }

        var id = $"{DateTimeOffset.UtcNow:yyyyMMddHHmmss}_{Guid.NewGuid():N}"[..24];
        var qFilePath = Path.Combine(QuarantineDirectory, $"{id}.aegisq");
        var metaPath = Path.Combine(QuarantineDirectory, $"{id}.json");

        var fileSize = new FileInfo(originalPath).Length;
        string sha256;

        try
        {
            if (fileSize <= MaxInMemoryGcmBytes)
            {
                // Single-pass TOCTOU-free read + SHA-256 + AES-256-GCM AEAD encryption
                byte[] plain;
                using (var input = new FileStream(originalPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    using var ms = new MemoryStream((int)Math.Min(fileSize, MaxInMemoryGcmBytes));
                    input.CopyTo(ms);
                    plain = ms.ToArray();
                }

                try
                {
                    fileSize = plain.Length;
                    sha256 = Convert.ToHexString(SHA256.HashData(plain));
                    var key = GetOrCreateAesKey();
                    var nonce = RandomNumberGenerator.GetBytes(GcmNonceSize);
                    var cipher = new byte[plain.Length];
                    var tag = new byte[GcmTagSize];
                    using (var aes = new AesGcm(key, GcmTagSize))
                    {
                        aes.Encrypt(nonce, plain, cipher, tag, AesGcmMagicHeader);
                    }

                    using var output = new FileStream(qFilePath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                    output.Write(AesGcmMagicHeader, 0, AesGcmMagicHeader.Length);
                    output.Write(nonce, 0, nonce.Length);
                    output.Write(tag, 0, tag.Length);
                    output.Write(cipher, 0, cipher.Length);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(plain);
                }
            }
            else
            {
                // Streaming single-pass fallback for unusually large (>64 MB) quarantined archives
                using var incHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                using var input = new FileStream(originalPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var output = new FileStream(qFilePath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                output.Write(LegacyMagicHeader, 0, LegacyMagicHeader.Length);
                var buffer = new byte[65536];
                int bytesRead;
                long offset = 0;
                while ((bytesRead = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    incHash.AppendData(buffer, 0, bytesRead);
                    for (int i = 0; i < bytesRead; i++)
                    {
                        buffer[i] ^= LegacyObfuscationKey[(offset + i) % LegacyObfuscationKey.Length];
                    }
                    output.Write(buffer, 0, bytesRead);
                    offset += bytesRead;
                }
                fileSize = offset;
                sha256 = Convert.ToHexString(incHash.GetHashAndReset());
            }
        }
        catch
        {
            try { if (File.Exists(qFilePath)) File.Delete(qFilePath); } catch { }
            throw;
        }

        bool deletedImmediately = TryDeleteWithRetry(originalPath, maxAttempts: 5);
        string finalReason = reason;
        if (!deletedImmediately)
        {
            // Schedule automatic OS kernel deletion on next reboot before any user process starts
            bool scheduled = Native.NativeMethods.MoveFileEx(originalPath, null, Native.NativeMethods.MOVEFILE_DELAY_UNTIL_REBOOT);
            finalReason = scheduled
                ? $"{reason} [사용 중 잠김 — 재부팅 시 OS 자동 삭제 예약됨]"
                : $"{reason} [원본 잠금 상태로 격리 사본 보관됨]";
        }

        var entry = new QuarantineEntry(
            id,
            originalPath,
            qFilePath,
            DateTimeOffset.Now,
            finalReason,
            sha256,
            fileSize);

        File.WriteAllText(metaPath, JsonSerializer.Serialize(entry, JsonOptions));

        return entry;
    }

    private static bool TryDeleteWithRetry(string path, int maxAttempts)
    {
        for (int attempt = 0; attempt < maxAttempts; attempt++)
        {
            try
            {
                if (!File.Exists(path)) return true;
                File.SetAttributes(path, FileAttributes.Normal);
                File.Delete(path);
                return true;
            }
            catch
            {
                if (attempt + 1 < maxAttempts)
                {
                    Thread.Sleep(50 * (attempt + 1));
                }
            }
        }
        return !File.Exists(path);
    }

    public bool RestoreFile(string entryId, string? overrideDestination = null)
    {
        if (string.IsNullOrWhiteSpace(entryId) || !System.Text.RegularExpressions.Regex.IsMatch(entryId, @"^[A-Za-z0-9_\-]+$"))
        {
            return false;
        }

        try
        {
            var metaPath = Path.Combine(QuarantineDirectory, $"{entryId}.json");
            if (!File.Exists(metaPath))
            {
                return false;
            }

            var entry = JsonSerializer.Deserialize<QuarantineEntry>(File.ReadAllText(metaPath));
            if (entry is null || string.IsNullOrWhiteSpace(entry.QuarantineFilePath) || !File.Exists(entry.QuarantineFilePath))
            {
                return false;
            }

            // Strictly confine QuarantineFilePath to QuarantineDirectory (prevents crafted JSON traversal)
            var qRoot = Path.GetFullPath(QuarantineDirectory).TrimEnd('\\') + "\\";
            var fullQFile = Path.GetFullPath(entry.QuarantineFilePath);
            if (!fullQFile.StartsWith(qRoot, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var destination = overrideDestination ?? entry.OriginalPath;
            if (IsProtectedSystemOrSelfPath(destination) || HasAnyReparsePointAncestor(destination))
            {
                return false;
            }
            if (File.Exists(destination))
            {
                if ((File.GetAttributes(destination) & FileAttributes.ReparsePoint) != 0)
                {
                    return false; // Never overwrite a symlink destination (Symlink Overwrite Escape defense)
                }
                try { File.SetAttributes(destination, FileAttributes.Normal); } catch { }
            }
            var destDir = Path.GetDirectoryName(destination);
            if (!string.IsNullOrEmpty(destDir))
            {
                Directory.CreateDirectory(destDir);
            }

            using (var input = new FileStream(fullQFile, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                var header = new byte[8];
                int readHeader = input.Read(header, 0, header.Length);
                if (readHeader != 8) return false;

                if (header.SequenceEqual(AesGcmMagicHeader))
                {
                    var nonce = new byte[GcmNonceSize];
                    var tag = new byte[GcmTagSize];
                    if (input.Read(nonce, 0, nonce.Length) != nonce.Length) return false;
                    if (input.Read(tag, 0, tag.Length) != tag.Length) return false;

                    long rawCipherLen = input.Length - input.Position;
                    if (rawCipherLen < 0 || rawCipherLen > MaxInMemoryGcmBytes) return false;
                    int cipherLen = (int)rawCipherLen;
                    var cipher = new byte[cipherLen];
                    int readCipher = 0;
                    while (readCipher < cipherLen)
                    {
                        int r = input.Read(cipher, readCipher, cipherLen - readCipher);
                        if (r <= 0) break;
                        readCipher += r;
                    }
                    if (readCipher != cipherLen) return false;

                    var plain = new byte[cipherLen];
                    try
                    {
                        using (var aes = new AesGcm(GetOrCreateAesKey(), GcmTagSize))
                        {
                            aes.Decrypt(nonce, cipher, tag, plain, AesGcmMagicHeader);
                        }

                        if (!string.IsNullOrWhiteSpace(entry.Sha256))
                        {
                            var actualSha = Convert.ToHexString(SHA256.HashData(plain));
                            if (!actualSha.Equals(entry.Sha256, StringComparison.OrdinalIgnoreCase))
                            {
                                return false;
                            }
                        }

                        File.WriteAllBytes(destination, plain);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(plain);
                    }
                }
                else if (header.SequenceEqual(LegacyMagicHeader))
                {
                    // Legacy AEGISQ1 restore: write to temp file + verify SHA-256 BEFORE atomic replace!
                    var tmpDest = destination + $".restore_{Guid.NewGuid():N}.tmp";
                    try
                    {
                        using var incHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                        using (var output = new FileStream(tmpDest, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                        {
                            var buffer = new byte[65536];
                            int bytesRead;
                            long offset = 0;
                            while ((bytesRead = input.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                for (int i = 0; i < bytesRead; i++)
                                {
                                    buffer[i] ^= LegacyObfuscationKey[(offset + i) % LegacyObfuscationKey.Length];
                                }
                                incHash.AppendData(buffer, 0, bytesRead);
                                output.Write(buffer, 0, bytesRead);
                                offset += bytesRead;
                            }
                        }

                        if (!string.IsNullOrWhiteSpace(entry.Sha256))
                        {
                            var actualSha = Convert.ToHexString(incHash.GetHashAndReset());
                            if (!actualSha.Equals(entry.Sha256, StringComparison.OrdinalIgnoreCase))
                            {
                                return false;
                            }
                        }

                        File.Move(tmpDest, destination, overwrite: true);
                    }
                    finally
                    {
                        try { if (File.Exists(tmpDest)) File.Delete(tmpDest); } catch { }
                    }
                }
                else
                {
                    return false;
                }
            }

            TryCancelPendingRebootDelete(destination);
            DeletePermanently(entryId);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void TryCancelPendingRebootDelete(string filePath)
    {
        try
        {
            var full = Path.GetFullPath(filePath);
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager", writable: true);
            // Note: When a single delete-on-reboot entry ("\??\C:\file\0\0\0") exists, .NET RegistryKey.GetValue
            // stops at the double-null and returns a 1-element string[] — so accept ops.Length >= 1!
            if (key?.GetValue("PendingFileRenameOperations") is not string[] ops || ops.Length < 1) return;

            var targetNt = @"\??\" + full;
            var filtered = new List<string>(ops.Length + 1);
            bool changed = false;
            for (int i = 0; i < ops.Length; i += 2)
            {
                var src = ops[i];
                var dst = i + 1 < ops.Length ? ops[i + 1] : string.Empty;
                if (string.IsNullOrEmpty(dst) && src.Equals(targetNt, StringComparison.OrdinalIgnoreCase))
                {
                    changed = true;
                    continue;
                }
                filtered.Add(src);
                filtered.Add(dst);
            }

            if (changed)
            {
                if (filtered.Count == 0) key.DeleteValue("PendingFileRenameOperations", throwOnMissingValue: false);
                else key.SetValue("PendingFileRenameOperations", filtered.ToArray(), Microsoft.Win32.RegistryValueKind.MultiString);
            }
        }
        catch { }
    }

    public bool DeletePermanently(string entryId)
    {
        if (string.IsNullOrWhiteSpace(entryId) || !System.Text.RegularExpressions.Regex.IsMatch(entryId, @"^[A-Za-z0-9_\-]+$"))
        {
            return false;
        }

        try
        {
            var qFilePath = Path.Combine(QuarantineDirectory, $"{entryId}.aegisq");
            var metaPath = Path.Combine(QuarantineDirectory, $"{entryId}.json");
            var deleted = false;

            if (File.Exists(qFilePath))
            {
                File.SetAttributes(qFilePath, FileAttributes.Normal);
                File.Delete(qFilePath);
                deleted = true;
            }

            if (File.Exists(metaPath))
            {
                File.SetAttributes(metaPath, FileAttributes.Normal);
                File.Delete(metaPath);
                deleted = true;
            }

            return deleted;
        }
        catch
        {
            return false;
        }
    }

    public IReadOnlyList<QuarantineEntry> ListEntries()
    {
        if (!Directory.Exists(QuarantineDirectory))
        {
            return Array.Empty<QuarantineEntry>();
        }

        var list = new List<QuarantineEntry>();
        foreach (var metaFile in Directory.GetFiles(QuarantineDirectory, "*.json"))
        {
            try
            {
                var entry = JsonSerializer.Deserialize<QuarantineEntry>(File.ReadAllText(metaFile));
                if (entry is not null)
                {
                    list.Add(entry);
                }
            }
            catch
            {
                // Skip unreadable metadata file.
            }
        }

        return list.OrderByDescending(e => e.QuarantinedAt).ToList();
    }

    public static bool IsProtectedSystemOrSelfPath(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath)) return true;
        string full;
        try { full = Path.GetFullPath(filePath); }
        catch { return true; }

        if (IsProtectedResolvedPath(full))
        {
            return true;
        }

        // Sharp-Edge Defense: Walk EVERY ancestor directory + file target so nested junctions
        // like C:\Users\Public\EvilJunction\System32\cmd.exe cannot bypass system protection!
        try
        {
            if (File.Exists(full))
            {
                var target = File.ResolveLinkTarget(full, returnFinalTarget: true);
                if (target is not null && IsProtectedResolvedPath(Path.GetFullPath(target.FullName)))
                {
                    return true;
                }
            }

            var cursor = Path.GetDirectoryName(full);
            int guard = 0;
            while (!string.IsNullOrEmpty(cursor) && guard++ < 64)
            {
                if (Directory.Exists(cursor))
                {
                    var dirTarget = Directory.ResolveLinkTarget(cursor, returnFinalTarget: true);
                    if (dirTarget is not null && IsProtectedResolvedPath(Path.GetFullPath(dirTarget.FullName)))
                    {
                        return true;
                    }
                }
                var next = Path.GetDirectoryName(cursor);
                if (string.Equals(next, cursor, StringComparison.OrdinalIgnoreCase)) break;
                cursor = next;
            }
        }
        catch { }

        return false;
    }

    public static bool HasAnyReparsePointAncestor(string filePath)
    {
        try
        {
            var cursor = Path.GetDirectoryName(Path.GetFullPath(filePath));
            int guard = 0;
            while (!string.IsNullOrEmpty(cursor) && guard++ < 64)
            {
                if (Directory.Exists(cursor) && (File.GetAttributes(cursor) & FileAttributes.ReparsePoint) != 0)
                {
                    return true;
                }
                var next = Path.GetDirectoryName(cursor);
                if (string.Equals(next, cursor, StringComparison.OrdinalIgnoreCase)) break;
                cursor = next;
            }
        }
        catch { }
        return false;
    }

    private static bool IsProtectedResolvedPath(string full)
    {
        var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\', '/');
        if (!string.IsNullOrEmpty(windowsDir) &&
            (full.StartsWith(windowsDir + "\\", StringComparison.OrdinalIgnoreCase) ||
             full.Equals(windowsDir, StringComparison.OrdinalIgnoreCase)))
        {
            // Allow quarantining malware dropped inside world-writable C:\Windows\Temp or C:\Windows\Tasks
            var winTemp = Path.Combine(windowsDir, "Temp") + "\\";
            var winTasks = Path.Combine(windowsDir, "Tasks") + "\\";
            if (!full.StartsWith(winTemp, StringComparison.OrdinalIgnoreCase) &&
                !full.StartsWith(winTasks, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        var selfBase = AppContext.BaseDirectory.TrimEnd('\\', '/');
        if (!string.IsNullOrEmpty(selfBase) &&
            (full.StartsWith(selfBase + "\\", StringComparison.OrdinalIgnoreCase) ||
             full.Equals(selfBase, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        var localDataRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AegisSentinel").TrimEnd('\\', '/');
        if (!string.IsNullOrEmpty(localDataRoot) &&
            (full.StartsWith(localDataRoot + "\\", StringComparison.OrdinalIgnoreCase) ||
             full.Equals(localDataRoot, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        if (Engine.ProcessRuleEvaluator.IsProtectedHostIdeProcess(full))
        {
            return true;
        }

        // Protect TrustedInstaller WindowsApps (Microsoft Store / Win11 inbox UWP) and Windows Defender folders
        var progFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).TrimEnd('\\', '/');
        var progFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86).TrimEnd('\\', '/');
        var progData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData).TrimEnd('\\', '/');

        if (!string.IsNullOrEmpty(progFiles) &&
            (full.StartsWith(Path.Combine(progFiles, "WindowsApps") + "\\", StringComparison.OrdinalIgnoreCase) ||
             full.StartsWith(Path.Combine(progFiles, "Windows Defender") + "\\", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        if (!string.IsNullOrEmpty(progFilesX86) &&
            full.StartsWith(Path.Combine(progFilesX86, "Windows Defender") + "\\", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!string.IsNullOrEmpty(progData) &&
            full.StartsWith(Path.Combine(progData, "Microsoft", "Windows Defender") + "\\", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }
}
