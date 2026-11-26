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
    private readonly Func<string, bool>? _deleteFileOverride;
    private readonly Func<string, bool>? _scheduleRebootDeleteOverride;
    private readonly Func<string, bool>? _cancelRebootDeleteOverride;
    private readonly Func<string, bool>? _isRebootDeleteScheduledOverride;
    private readonly Action<string, string>? _writeMetadataOverride;
    private readonly Action<string, byte[]>? _writeRestoreTempOverride;
    private readonly long _maxInMemoryGcmBytes;
    private byte[]? _cachedAesKey;

    public string QuarantineDirectory { get; }

    public QuarantineManager(
        string? baseDirectory = null,
        Func<string, bool>? deleteFileOverride = null,
        Func<string, bool>? scheduleRebootDeleteOverride = null,
        Action<string, string>? writeMetadataOverride = null,
        Action<string, byte[]>? writeRestoreTempOverride = null,
        long maxInMemoryGcmBytes = MaxInMemoryGcmBytes,
        Func<string, bool>? cancelRebootDeleteOverride = null,
        Func<string, bool>? isRebootDeleteScheduledOverride = null)
    {
        var root = baseDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AegisSentinel");
        QuarantineDirectory = Path.Combine(root, "Quarantine");
        Directory.CreateDirectory(QuarantineDirectory);
        _keyFilePath = Path.Combine(QuarantineDirectory, ".quarantine_aes.key");
        _deleteFileOverride = deleteFileOverride;
        _scheduleRebootDeleteOverride = scheduleRebootDeleteOverride;
        _cancelRebootDeleteOverride = cancelRebootDeleteOverride;
        _isRebootDeleteScheduledOverride = isRebootDeleteScheduledOverride;
        _writeMetadataOverride = writeMetadataOverride;
        _writeRestoreTempOverride = writeRestoreTempOverride;
        _maxInMemoryGcmBytes = Math.Max(0, maxInMemoryGcmBytes);
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
            if (fileSize <= _maxInMemoryGcmBytes)
            {
                // Single-pass TOCTOU-free read + SHA-256 + AES-256-GCM AEAD encryption
                byte[] plain;
                using (var input = new FileStream(originalPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    using var ms = new MemoryStream((int)Math.Min(fileSize, _maxInMemoryGcmBytes));
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
                    output.Flush(flushToDisk: true);
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
                output.Flush(flushToDisk: true);
                fileSize = offset;
                sha256 = Convert.ToHexString(incHash.GetHashAndReset());
            }
        }
        catch
        {
            try { if (File.Exists(qFilePath)) File.Delete(qFilePath); } catch { }
            throw;
        }

        // Crash-safe commit order (P1-4):
        // Persist restore metadata atomically to disk BEFORE deleting the original file or scheduling reboot delete.
        // If metadata persistence fails, abort cleanly leaving the original untouched and unscheduled.
        var pendingEntry = new QuarantineEntry(
            id,
            originalPath,
            qFilePath,
            DateTimeOffset.Now,
            reason,
            sha256,
            fileSize,
            QuarantineDisposition.PendingOriginalRemoval);

        try
        {
            WriteMetadataAtomic(metaPath, JsonSerializer.Serialize(pendingEntry, JsonOptions));
        }
        catch
        {
            try { if (File.Exists(qFilePath)) File.Delete(qFilePath); } catch { }
            try { if (File.Exists(metaPath)) File.Delete(metaPath); } catch { }
            throw;
        }

        bool deletedImmediately = _deleteFileOverride is not null
            ? _deleteFileOverride(originalPath)
            : TryDeleteWithRetry(originalPath, maxAttempts: 5);

        QuarantineDisposition disposition;
        string finalReason = reason;
        if (deletedImmediately)
        {
            disposition = QuarantineDisposition.RemovedImmediately;
        }
        else
        {
            // Schedule automatic OS kernel deletion on next reboot before any user process starts
            bool scheduled = _scheduleRebootDeleteOverride is not null
                ? _scheduleRebootDeleteOverride(originalPath)
                : Native.NativeMethods.MoveFileEx(originalPath, null, Native.NativeMethods.MOVEFILE_DELAY_UNTIL_REBOOT);
            if (scheduled)
            {
                disposition = QuarantineDisposition.ScheduledDeleteOnReboot;
                finalReason = $"{reason} [사용 중 잠김 — 재부팅 시 OS 자동 삭제 예약됨]";
            }
            else
            {
                disposition = QuarantineDisposition.CopyOnlyOriginalLocked;
                finalReason = $"{reason} [원본 잠금 상태로 격리 사본만 보관됨 — 원본 미제거]";
            }
        }

        var entry = pendingEntry with
        {
            Reason = finalReason,
            Disposition = disposition
        };

        try
        {
            WriteMetadataAtomic(metaPath, JsonSerializer.Serialize(entry, JsonOptions));
        }
        catch
        {
            // PendingOriginalRemoval metadata is already safely persisted on disk and will be reconciled on next load.
        }

        return entry;
    }

    private void WriteMetadataAtomic(string metaPath, string json)
    {
        if (_writeMetadataOverride is not null)
        {
            _writeMetadataOverride(metaPath, json);
            return;
        }

        var dir = Path.GetDirectoryName(metaPath) ?? QuarantineDirectory;
        var tmpPath = Path.Combine(dir, $".{Path.GetFileName(metaPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            var bytes = Encoding.UTF8.GetBytes(json);
            using (var fs = new FileStream(tmpPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                fs.Write(bytes, 0, bytes.Length);
                fs.Flush(flushToDisk: true);
            }

            if (File.Exists(metaPath))
            {
                File.Replace(tmpPath, metaPath, destinationBackupFileName: null, ignoreMetadataErrors: true);
            }
            else
            {
                File.Move(tmpPath, metaPath, overwrite: false);
            }

            TryFlushDirectoryMetadata(dir);
        }
        finally
        {
            try { if (File.Exists(tmpPath)) File.Delete(tmpPath); } catch { }
        }
    }

    private static void TryFlushDirectoryMetadata(string? directoryPath)
    {
        if (string.IsNullOrWhiteSpace(directoryPath)) return;
        try
        {
            var handle = Native.NativeMethods.CreateFileW(
                directoryPath,
                Native.NativeMethods.GENERIC_WRITE,
                Native.NativeMethods.FILE_SHARE_READ | Native.NativeMethods.FILE_SHARE_WRITE | Native.NativeMethods.FILE_SHARE_DELETE,
                IntPtr.Zero,
                Native.NativeMethods.OPEN_EXISTING,
                Native.NativeMethods.FILE_FLAG_BACKUP_SEMANTICS,
                IntPtr.Zero);
            if (handle != IntPtr.Zero && handle != new IntPtr(-1))
            {
                try { _ = Native.NativeMethods.FlushFileBuffers(handle); }
                finally { Native.NativeMethods.CloseHandle(handle); }
            }
        }
        catch { }
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

    public bool RestoreFile(string entryId, string? overrideDestination = null, bool overwriteExisting = false) =>
        RestoreFileDetailed(entryId, overrideDestination, overwriteExisting).Success;

    public QuarantineRestoreResult RestoreFileDetailed(
        string entryId,
        string? overrideDestination = null,
        bool overwriteExisting = false)
    {
        if (string.IsNullOrWhiteSpace(entryId) || !System.Text.RegularExpressions.Regex.IsMatch(entryId, @"^[A-Za-z0-9_\-]+$"))
        {
            return new QuarantineRestoreResult(QuarantineRestoreStatus.NotFoundOrInvalid, string.Empty, "유효하지 않은 격리 항목 ID입니다.");
        }

        string destination = overrideDestination ?? string.Empty;
        try
        {
            var metaPath = Path.Combine(QuarantineDirectory, $"{entryId}.json");
            if (!File.Exists(metaPath))
            {
                return new QuarantineRestoreResult(QuarantineRestoreStatus.NotFoundOrInvalid, destination, "격리 메타데이터를 찾을 수 없습니다.");
            }

            var entry = JsonSerializer.Deserialize<QuarantineEntry>(File.ReadAllText(metaPath));
            if (entry is null || string.IsNullOrWhiteSpace(entry.QuarantineFilePath) || !File.Exists(entry.QuarantineFilePath))
            {
                return new QuarantineRestoreResult(QuarantineRestoreStatus.NotFoundOrInvalid, destination, "격리 사본 파일이 존재하지 않습니다.");
            }

            // Strictly confine QuarantineFilePath to QuarantineDirectory (prevents crafted JSON traversal)
            var qRoot = Path.GetFullPath(QuarantineDirectory).TrimEnd('\\') + "\\";
            var fullQFile = Path.GetFullPath(entry.QuarantineFilePath);
            if (!fullQFile.StartsWith(qRoot, StringComparison.OrdinalIgnoreCase))
            {
                return new QuarantineRestoreResult(QuarantineRestoreStatus.NotFoundOrInvalid, destination, "격리 파일 경로가 격리 디렉터리 범위를 벗어났습니다.");
            }

            destination = Path.GetFullPath(overrideDestination ?? entry.OriginalPath);
            if (IsProtectedSystemOrSelfPath(destination) || HasAnyReparsePointAncestor(destination))
            {
                return new QuarantineRestoreResult(QuarantineRestoreStatus.NotFoundOrInvalid, destination, "보호된 시스템/보안 경로 또는 리파스 포인트 하위 경로에는 복원할 수 없습니다.");
            }

            bool destinationExists = File.Exists(destination);
            if (destinationExists)
            {
                if ((File.GetAttributes(destination) & FileAttributes.ReparsePoint) != 0)
                {
                    return new QuarantineRestoreResult(QuarantineRestoreStatus.NotFoundOrInvalid, destination, "복원 대상 경로가 심볼릭 링크/리파스 포인트이므로 차단되었습니다.");
                }

                if (!overwriteExisting)
                {
                    return new QuarantineRestoreResult(
                        QuarantineRestoreStatus.DestinationConflict,
                        destination,
                        $"복원 대상 위치에 이미 파일이 존재합니다: {destination}");
                }
            }

            var destDir = Path.GetDirectoryName(destination);
            if (!string.IsNullOrEmpty(destDir))
            {
                Directory.CreateDirectory(destDir);
            }

            var tmpDest = Path.Combine(
                string.IsNullOrEmpty(destDir) ? QuarantineDirectory : destDir,
                $".{Path.GetFileName(destination)}.restore_{Guid.NewGuid():N}.tmp");

            try
            {
                using (var input = new FileStream(fullQFile, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    var header = new byte[8];
                    int readHeader = input.Read(header, 0, header.Length);
                    if (readHeader != 8)
                    {
                        return new QuarantineRestoreResult(QuarantineRestoreStatus.IntegrityCheckFailed, destination, "격리 파일 헤더가 손상되었습니다.");
                    }

                    if (header.SequenceEqual(AesGcmMagicHeader))
                    {
                        var nonce = new byte[GcmNonceSize];
                        var tag = new byte[GcmTagSize];
                        if (input.Read(nonce, 0, nonce.Length) != nonce.Length ||
                            input.Read(tag, 0, tag.Length) != tag.Length)
                        {
                            return new QuarantineRestoreResult(QuarantineRestoreStatus.IntegrityCheckFailed, destination, "AES-GCM 메타데이터가 손상되었습니다.");
                        }

                        long rawCipherLen = input.Length - input.Position;
                        if (rawCipherLen < 0 || rawCipherLen > MaxInMemoryGcmBytes)
                        {
                            return new QuarantineRestoreResult(QuarantineRestoreStatus.IntegrityCheckFailed, destination, "격리 파일 크기가 비정상적입니다.");
                        }

                        int cipherLen = (int)rawCipherLen;
                        var cipher = new byte[cipherLen];
                        int readCipher = 0;
                        while (readCipher < cipherLen)
                        {
                            int r = input.Read(cipher, readCipher, cipherLen - readCipher);
                            if (r <= 0) break;
                            readCipher += r;
                        }
                        if (readCipher != cipherLen)
                        {
                            return new QuarantineRestoreResult(QuarantineRestoreStatus.IntegrityCheckFailed, destination, "격리 파일 본문을 끝까지 읽지 못했습니다.");
                        }

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
                                    return new QuarantineRestoreResult(QuarantineRestoreStatus.IntegrityCheckFailed, destination, "복호화 데이터 SHA-256 무결성 검증에 실패했습니다.");
                                }
                            }

                            WriteRestoreTempFile(tmpDest, plain);
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(plain);
                        }
                    }
                    else if (header.SequenceEqual(LegacyMagicHeader))
                    {
                        if (_writeRestoreTempOverride is not null)
                        {
                            using var ms = new MemoryStream();
                            var buffer = new byte[65536];
                            int bytesRead;
                            long offset = 0;
                            while ((bytesRead = input.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                for (int i = 0; i < bytesRead; i++)
                                {
                                    buffer[i] ^= LegacyObfuscationKey[(offset + i) % LegacyObfuscationKey.Length];
                                }
                                ms.Write(buffer, 0, bytesRead);
                                offset += bytesRead;
                            }
                            var decrypted = ms.ToArray();
                            try
                            {
                                WriteRestoreTempFile(tmpDest, decrypted);
                            }
                            finally
                            {
                                CryptographicOperations.ZeroMemory(decrypted);
                            }
                        }
                        else
                        {
                            using var output = new FileStream(tmpDest, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                            var buffer = new byte[65536];
                            int bytesRead;
                            long offset = 0;
                            while ((bytesRead = input.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                for (int i = 0; i < bytesRead; i++)
                                {
                                    buffer[i] ^= LegacyObfuscationKey[(offset + i) % LegacyObfuscationKey.Length];
                                }
                                output.Write(buffer, 0, bytesRead);
                                offset += bytesRead;
                            }
                            output.Flush(flushToDisk: true);
                        }
                    }
                    else
                    {
                        return new QuarantineRestoreResult(QuarantineRestoreStatus.IntegrityCheckFailed, destination, "지원되지 않는 격리 파일 형식입니다.");
                    }
                }

                // Re-verify SHA-256 directly on the flushed temp file BEFORE replacing destination.
                if (!File.Exists(tmpDest))
                {
                    return new QuarantineRestoreResult(QuarantineRestoreStatus.WriteFailed, destination, "임시 복원 파일 생성에 실패했습니다.");
                }

                if (!string.IsNullOrWhiteSpace(entry.Sha256))
                {
                    using var verifyStream = new FileStream(tmpDest, FileMode.Open, FileAccess.Read, FileShare.Read);
                    var diskSha = Convert.ToHexString(SHA256.HashData(verifyStream));
                    if (!diskSha.Equals(entry.Sha256, StringComparison.OrdinalIgnoreCase))
                    {
                        return new QuarantineRestoreResult(QuarantineRestoreStatus.IntegrityCheckFailed, destination, "디스크 임시 복원 파일의 SHA-256 검증에 실패했습니다.");
                    }
                }

                // Commit atomically into destination: existing file is never partially overwritten on temp write failure!
                if (overwriteExisting && File.Exists(destination))
                {
                    if ((File.GetAttributes(destination) & FileAttributes.ReparsePoint) != 0)
                    {
                        return new QuarantineRestoreResult(QuarantineRestoreStatus.NotFoundOrInvalid, destination, "복원 대상 경로가 심볼릭 링크/리파스 포인트로 변경되었습니다.");
                    }
                    try { File.SetAttributes(destination, FileAttributes.Normal); } catch { }
                    File.Replace(tmpDest, destination, destinationBackupFileName: null, ignoreMetadataErrors: true);
                    TryFlushDirectoryMetadata(destDir);
                }
                else
                {
                    try
                    {
                        File.Move(tmpDest, destination, overwrite: false);
                        TryFlushDirectoryMetadata(destDir);
                    }
                    catch (IOException) when (!overwriteExisting && File.Exists(destination))
                    {
                        return new QuarantineRestoreResult(
                            QuarantineRestoreStatus.DestinationConflict,
                            destination,
                            $"복원 대상 위치에 파일이 이미 존재합니다: {destination}");
                    }
                }
            }
            finally
            {
                try { if (File.Exists(tmpDest)) File.Delete(tmpDest); } catch { }
            }

            bool hasPendingRebootDelete =
                entry.Disposition == QuarantineDisposition.ScheduledDeleteOnReboot ||
                !TryCheckPendingRebootDeleteScheduled(destination, out bool scheduledInRegistry) ||
                scheduledInRegistry;

            bool rebootDeleteCancelConfirmed = TryCancelPendingRebootDelete(destination, requireConfirmedRemoval: hasPendingRebootDelete);
            if (!rebootDeleteCancelConfirmed)
            {
                // Preserve quarantine copy + metadata so next reboot's pending OS delete cannot cause permanent data loss!
                return new QuarantineRestoreResult(
                    QuarantineRestoreStatus.RestoredButRebootDeleteCancelFailed,
                    destination,
                    $"파일은 복원되었으나 재부팅 시 OS 자동 삭제 예약 취소에 실패했습니다. 다음 부팅 시 복원된 파일이 삭제될 수 있으므로 격리 사본을 보존했습니다: {destination}");
            }

            DeletePermanently(entryId);
            return new QuarantineRestoreResult(QuarantineRestoreStatus.Restored, destination, $"복원 완료: {destination}");
        }
        catch (CryptographicException ex)
        {
            return new QuarantineRestoreResult(QuarantineRestoreStatus.IntegrityCheckFailed, destination, $"복호화/무결성 검증 실패: {ex.Message}");
        }
        catch (Exception ex)
        {
            return new QuarantineRestoreResult(QuarantineRestoreStatus.WriteFailed, destination, $"파일 쓰기/복원 실패: {ex.Message}");
        }
    }

    private void WriteRestoreTempFile(string tempPath, byte[] plain)
    {
        if (_writeRestoreTempOverride is not null)
        {
            _writeRestoreTempOverride(tempPath, plain);
            return;
        }

        using var output = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        output.Write(plain, 0, plain.Length);
        output.Flush(flushToDisk: true);
    }

    private bool IsPendingRebootDeleteScheduled(string filePath) =>
        TryCheckPendingRebootDeleteScheduled(filePath, out bool isScheduled) && isScheduled;

    private bool TryCheckPendingRebootDeleteScheduled(string filePath, out bool isScheduled)
    {
        if (_isRebootDeleteScheduledOverride is not null)
        {
            isScheduled = _isRebootDeleteScheduledOverride(filePath);
            return true;
        }

        try
        {
            var full = Path.GetFullPath(filePath);
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager", writable: false);
            if (key is null)
            {
                isScheduled = false;
                return false;
            }
            if (key.GetValue("PendingFileRenameOperations") is not string[] ops || ops.Length < 1)
            {
                isScheduled = false;
                return true;
            }

            var targetNt = @"\??\" + full;
            for (int i = 0; i < ops.Length; i += 2)
            {
                var src = ops[i];
                var dst = i + 1 < ops.Length ? ops[i + 1] : string.Empty;
                if (string.IsNullOrEmpty(dst) && src.Equals(targetNt, StringComparison.OrdinalIgnoreCase))
                {
                    isScheduled = true;
                    return true;
                }
            }
            isScheduled = false;
            return true;
        }
        catch
        {
            isScheduled = false;
            return false;
        }
    }

    private bool TryCancelPendingRebootDelete(string filePath, bool requireConfirmedRemoval)
    {
        if (_cancelRebootDeleteOverride is not null)
        {
            return _cancelRebootDeleteOverride(filePath);
        }

        bool checkSucceeded = TryCheckPendingRebootDeleteScheduled(filePath, out bool currentlyScheduled);
        if (checkSucceeded && !currentlyScheduled)
        {
            // Confirmed not scheduled in PendingFileRenameOperations — no HKLM write required.
            return true;
        }

        try
        {
            var full = Path.GetFullPath(filePath);
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager", writable: true);
            if (key is null)
            {
                return !requireConfirmedRemoval && checkSucceeded && !currentlyScheduled;
            }

            // Note: When a single delete-on-reboot entry ("\??\C:\file\0\0\0") exists, .NET RegistryKey.GetValue
            // stops at the double-null and returns a 1-element string[] — so accept ops.Length >= 1!
            if (key.GetValue("PendingFileRenameOperations") is not string[] ops || ops.Length < 1)
            {
                return true;
            }

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

            // Confirm via re-read that the pending reboot delete entry is genuinely gone.
            return TryCheckPendingRebootDeleteScheduled(filePath, out bool stillScheduled) && !stillScheduled;
        }
        catch
        {
            return false;
        }
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
                    if (entry.Disposition == QuarantineDisposition.PendingOriginalRemoval)
                    {
                        // Crash-recovery reconciliation: inspect actual disk & OS reboot-delete queue state.
                        bool originalStillPresent = !string.IsNullOrWhiteSpace(entry.OriginalPath) && File.Exists(entry.OriginalPath);
                        if (!originalStillPresent)
                        {
                            entry = entry with
                            {
                                Disposition = QuarantineDisposition.RemovedImmediately
                            };
                        }
                        else if (IsPendingRebootDeleteScheduled(entry.OriginalPath))
                        {
                            entry = entry with
                            {
                                Disposition = QuarantineDisposition.ScheduledDeleteOnReboot,
                                Reason = entry.Reason.Contains("재부팅", StringComparison.Ordinal)
                                    ? entry.Reason
                                    : $"{entry.Reason} [중단 복구 확인 — 재부팅 시 OS 자동 삭제 예약됨]"
                            };
                        }
                        else
                        {
                            entry = entry with
                            {
                                Disposition = QuarantineDisposition.CopyOnlyOriginalLocked,
                                Reason = entry.Reason.Contains("중단 복구", StringComparison.Ordinal)
                                    ? entry.Reason
                                    : $"{entry.Reason} [중단 복구 확인 — 원본 파일 잔존]"
                            };
                        }
                        try
                        {
                            WriteMetadataAtomic(metaFile, JsonSerializer.Serialize(entry, JsonOptions));
                        }
                        catch { }
                    }
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
