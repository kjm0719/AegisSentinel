using System.Collections.Concurrent;
using System.Text.Json;
using AegisSentinel.Core.Engine;
using AegisSentinel.Core.Models;

namespace AegisSentinel.Core.Services;

/// <summary>
/// Maintains a silent, anti-poisoning local backup vault of high-value user documents
/// so files damaged before ransomware freeze can be restored with one click.
/// </summary>
public sealed class RecoveryVault
{
    private const long MaxSingleFileBytes = 5 * 1024 * 1024; // 5 MB
    private const long MaxTotalVaultBytes = 200 * 1024 * 1024; // 200 MB rolling budget

    private static readonly HashSet<string> HighValueExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".docx", ".xlsx", ".pptx", ".pdf", ".hwp", ".hwpx",
        ".txt", ".md", ".json", ".yaml", ".yml", ".env", ".sql",
        ".pem", ".key", ".ppk", ".csv"
    };

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly ConcurrentDictionary<string, VaultSnapshotEntry> _index = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _sync = new();
    private readonly PolicyIntegritySigner _signer;

    public string VaultDirectory { get; }
    private string IndexFilePath => Path.Combine(VaultDirectory, "vault_index.json");

    public RecoveryVault(string? baseDirectory = null, PolicyIntegritySigner? sharedSigner = null)
    {
        var root = baseDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AegisSentinel");
        VaultDirectory = Path.Combine(root, "Vault");
        Directory.CreateDirectory(VaultDirectory);
        _signer = sharedSigner ?? new PolicyIntegritySigner(root);
        LoadIndex();
    }

    public int SnapshotProtectedFolders(IEnumerable<string> folders, int maxFilesPerFolder = 150)
    {
        int captured = 0;
        var enumOpts = new EnumerationOptions
        {
            AttributesToSkip = FileAttributes.ReparsePoint,
            IgnoreInaccessible = true,
            RecurseSubdirectories = true,
            MaxRecursionDepth = 3
        };

        foreach (var folder in folders)
        {
            if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder))
            {
                continue;
            }

            try
            {
                int eligibleCount = 0;
                foreach (var file in Directory.EnumerateFiles(folder, "*.*", enumOpts))
                {
                    if (eligibleCount >= maxFilesPerFolder) break;
                    if (file.StartsWith(VaultDirectory, StringComparison.OrdinalIgnoreCase)) continue;

                    var ext = Path.GetExtension(file);
                    bool isSshKey = file.Contains(@"\.ssh\", StringComparison.OrdinalIgnoreCase);
                    if (!isSshKey && !HighValueExtensions.Contains(ext)) continue;

                    eligibleCount++;
                    if (TrySnapshotFile(file))
                    {
                        captured++;
                    }
                }
            }
            catch { }
        }

        return captured;
    }

    public bool TrySnapshotFile(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return false;
        }

        var fileName = Path.GetFileName(filePath);
        if (fileName.StartsWith("!_", StringComparison.Ordinal) || fileName.StartsWith("~$", StringComparison.Ordinal))
        {
            return false;
        }

        var ext = Path.GetExtension(filePath);
        bool isSshKey = filePath.Contains(@"\.ssh\", StringComparison.OrdinalIgnoreCase);
        if (!isSshKey && !HighValueExtensions.Contains(ext))
        {
            return false;
        }

        string? snapPath = null;
        try
        {
            var fullPath = Path.GetFullPath(filePath);
            var info = new FileInfo(fullPath);
            if ((info.Attributes & FileAttributes.ReparsePoint) != 0 || QuarantineManager.HasAnyReparsePointAncestor(fullPath))
            {
                return false; // Never follow symlinks during silent document snapshotting
            }
            if (info.Length == 0 || info.Length > MaxSingleFileBytes)
            {
                return false;
            }

            var id = $"{DateTimeOffset.UtcNow:yyyyMMddHHmmss}_{Guid.NewGuid():N}"[..24];
            snapPath = Path.Combine(VaultDirectory, $"{id}.snap");

            // Copy first with ReadWrite|Delete sharing so open Word/HWP documents succeed and TOCTOU poisoning is impossible!
            long copiedBytes = 0;
            using (var input = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (var output = new FileStream(snapPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                var buffer = new byte[65536];
                int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    copiedBytes += read;
                    if (copiedBytes > MaxSingleFileBytes)
                    {
                        break;
                    }
                    output.Write(buffer, 0, read);
                }
            }

            if (copiedBytes == 0 || copiedBytes > MaxSingleFileBytes)
            {
                try { File.Delete(snapPath); } catch { }
                return false;
            }

            // Anti-poisoning check directly on the captured snapshot copy using the original file's extension!
            var effectiveExt = isSshKey && string.IsNullOrEmpty(ext) ? ".pem" : ext;
            var entropy = EntropyAnalyzer.AnalyzeFile(snapPath, extensionOverride: effectiveExt);
            if (entropy.IsLikelyEncrypted)
            {
                try { File.Delete(snapPath); } catch { }
                return false;
            }

            var sha256 = SignatureVerifier.ComputeSha256(snapPath);
            lock (_sync)
            {
                if (_index.TryGetValue(fullPath, out var existing) &&
                    existing.Sha256.Equals(sha256, StringComparison.OrdinalIgnoreCase) &&
                    File.Exists(existing.SnapshotPath))
                {
                    try { File.Delete(snapPath); } catch { }
                    return false;
                }

                long netDelta = existing is not null ? Math.Max(0, copiedBytes - existing.FileSize) : copiedBytes;
                EnforceBudget(netDelta);
                try { File.SetAttributes(snapPath, FileAttributes.ReadOnly | FileAttributes.Hidden); } catch { }

                if (existing is not null && File.Exists(existing.SnapshotPath))
                {
                    try
                    {
                        File.SetAttributes(existing.SnapshotPath, FileAttributes.Normal);
                        File.Delete(existing.SnapshotPath);
                    }
                    catch { }
                }

                var entry = new VaultSnapshotEntry(id, fullPath, snapPath, DateTimeOffset.Now, sha256, copiedBytes);
                _index[fullPath] = entry;
                SaveIndex();
                snapPath = null; // Ownership transferred to index
                return true;
            }
        }
        catch
        {
            if (!string.IsNullOrEmpty(snapPath))
            {
                try
                {
                    if (File.Exists(snapPath))
                    {
                        File.SetAttributes(snapPath, FileAttributes.Normal);
                        File.Delete(snapPath);
                    }
                }
                catch { }
            }
            return false;
        }
    }

    public bool RestoreSnapshot(string snapshotId, string? overridePath = null)
    {
        lock (_sync)
        {
            try
            {
                var entry = _index.Values.FirstOrDefault(e => e.Id.Equals(snapshotId, StringComparison.OrdinalIgnoreCase));
                if (entry is null || !File.Exists(entry.SnapshotPath))
                {
                    return false;
                }

                // Confine snapshot path strictly to VaultDirectory
                var vaultRoot = Path.GetFullPath(VaultDirectory).TrimEnd('\\') + "\\";
                var fullSnap = Path.GetFullPath(entry.SnapshotPath);
                if (!fullSnap.StartsWith(vaultRoot, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                var destination = overridePath ?? entry.OriginalPath;
                if (QuarantineManager.IsProtectedSystemOrSelfPath(destination) ||
                    QuarantineManager.HasAnyReparsePointAncestor(destination))
                {
                    return false;
                }

                if (!string.IsNullOrWhiteSpace(entry.Sha256))
                {
                    var snapSha = SignatureVerifier.ComputeSha256(fullSnap);
                    if (!snapSha.Equals(entry.Sha256, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }
                }

                if (File.Exists(destination))
                {
                    if ((File.GetAttributes(destination) & FileAttributes.ReparsePoint) != 0)
                    {
                        return false;
                    }
                    try { File.SetAttributes(destination, FileAttributes.Normal); } catch { }
                }
                var dir = Path.GetDirectoryName(destination);
                if (!string.IsNullOrEmpty(dir))
                {
                    Directory.CreateDirectory(dir);
                }
                File.Copy(fullSnap, destination, overwrite: true);
                try { File.SetAttributes(destination, FileAttributes.Normal); } catch { }
                return true;
            }
            catch
            {
                return false;
            }
        }
    }

    public IReadOnlyList<VaultSnapshotEntry> ListSnapshots()
    {
        return _index.Values
            .Where(e => File.Exists(e.SnapshotPath))
            .OrderByDescending(e => e.CapturedAt)
            .ToList();
    }

    private void EnforceBudget(long incomingBytes)
    {
        long total = _index.Values.Sum(v => v.FileSize);
        if (total + incomingBytes <= MaxTotalVaultBytes)
        {
            return;
        }

        foreach (var oldest in _index.Values.OrderBy(v => v.CapturedAt).ToList())
        {
            if (total + incomingBytes <= MaxTotalVaultBytes)
            {
                break;
            }

            try
            {
                if (File.Exists(oldest.SnapshotPath))
                {
                    File.SetAttributes(oldest.SnapshotPath, FileAttributes.Normal);
                    File.Delete(oldest.SnapshotPath);
                }
            }
            catch { }

            _index.TryRemove(oldest.OriginalPath, out _);
            total -= oldest.FileSize;
        }
    }

    private void LoadIndex()
    {
        try
        {
            if (!File.Exists(IndexFilePath))
            {
                return;
            }

            if (!_signer.VerifyFile(IndexFilePath, out _))
            {
                return; // Reject tampered or unsealed vault_index.json!
            }

            var entries = JsonSerializer.Deserialize<List<VaultSnapshotEntry>>(File.ReadAllText(IndexFilePath));
            if (entries is null)
            {
                return;
            }

            var vaultRoot = Path.GetFullPath(VaultDirectory).TrimEnd('\\') + "\\";
            foreach (var entry in entries)
            {
                if (!string.IsNullOrWhiteSpace(entry.SnapshotPath) &&
                    File.Exists(entry.SnapshotPath) &&
                    Path.GetFullPath(entry.SnapshotPath).StartsWith(vaultRoot, StringComparison.OrdinalIgnoreCase))
                {
                    _index[entry.OriginalPath] = entry;
                }
            }
        }
        catch { }
    }

    private void SaveIndex()
    {
        try
        {
            var list = _index.Values.ToList();
            var tmp = IndexFilePath + $".{Guid.NewGuid():N}.tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(list, JsonOptions));
            if (File.Exists(IndexFilePath))
            {
                try { File.SetAttributes(IndexFilePath, FileAttributes.Normal); } catch { }
            }
            File.Move(tmp, IndexFilePath, overwrite: true);
            _signer.SignFile(IndexFilePath);
        }
        catch { }
    }
}
