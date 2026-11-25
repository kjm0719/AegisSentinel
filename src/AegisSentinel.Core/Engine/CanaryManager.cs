using System.Collections.Concurrent;
using System.Text;
using AegisSentinel.Core.Services;

namespace AegisSentinel.Core.Engine;

public sealed class CanaryManager
{
    private static readonly string[] CanaryFileNames =
    {
        "!_00_aegis_canary.docx",
        "!_zz_aegis_canary.txt"
    };

    private const string CanaryContentHeader = "AEGIS-SENTINEL-CANARY-DO-NOT-MODIFY-";
    private readonly ConcurrentDictionary<string, string> _canaryHashes = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyCollection<string> CanaryPaths => _canaryHashes.Keys.ToList();

    public void DeployCanaries(IEnumerable<string> protectedFolders)
    {
        RemoveLegacyDesktopAndDownloadCanaries();

        var desktopDir = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var downloadsDir = Path.Combine(userProfile, "Downloads");

        foreach (var folder in protectedFolders)
        {
            if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder))
            {
                continue;
            }

            // Do not drop office-style canary files inside credential dotfiles (.ssh/.aws)
            // or directly on the user's Desktop / Downloads where Show-Hidden-Files users might delete them manually.
            var trimmed = folder.TrimEnd('\\', '/');
            var folderName = Path.GetFileName(trimmed);
            if (folderName.StartsWith('.') ||
                trimmed.Equals(desktopDir.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase) ||
                trimmed.Equals(downloadsDir.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            foreach (var name in CanaryFileNames)
            {
                var path = Path.GetFullPath(Path.Combine(folder, name));
                try
                {
                    if (!File.Exists(path))
                    {
                        var payload = Encoding.UTF8.GetBytes($"{CanaryContentHeader}{Guid.NewGuid():N}\n");
                        File.WriteAllBytes(path, payload);
                        File.SetAttributes(path, FileAttributes.Hidden);
                    }

                    var hash = SignatureVerifier.ComputeSha256(path);
                    _canaryHashes[path] = hash;
                }
                catch
                {
                    // Skip folders without write permission.
                }
            }
        }
    }

    private static void RemoveLegacyDesktopAndDownloadCanaries()
    {
        try
        {
            var desktopDir = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            var downloadsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
            foreach (var folder in new[] { desktopDir, downloadsDir })
            {
                if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder)) continue;
                foreach (var name in CanaryFileNames)
                {
                    var path = Path.Combine(folder, name);
                    try
                    {
                        if (File.Exists(path))
                        {
                            File.SetAttributes(path, FileAttributes.Normal);
                            File.Delete(path);
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }
    }

    public static bool IsCanaryFileIntactOnDisk(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath)) return false;

        for (int attempt = 0; attempt < 3; attempt++)
        {
            if (!File.Exists(filePath))
            {
                if (attempt < 2) { Thread.Sleep(25); continue; }
                return false;
            }

            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                var buf = new byte[128];
                int read = fs.Read(buf, 0, buf.Length);
                if (read <= 0) return false;
                var text = Encoding.UTF8.GetString(buf, 0, read);
                return text.StartsWith(CanaryContentHeader, StringComparison.Ordinal);
            }
            catch (IOException) when (attempt < 2)
            {
                Thread.Sleep(30);
            }
            catch
            {
                return false;
            }
        }
        return false;
    }

    public bool IsCanaryPath(string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            return false;
        }

        try
        {
            var full = Path.GetFullPath(filePath);
            if (_canaryHashes.ContainsKey(full))
            {
                return true;
            }
        }
        catch { }

        var name = Path.GetFileName(filePath);
        return CanaryFileNames.Contains(name, StringComparer.OrdinalIgnoreCase);
    }

    public bool VerifyCanaryIntact(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return false;
        }

        string full;
        try { full = Path.GetFullPath(filePath); }
        catch { full = filePath; }

        if (!_canaryHashes.TryGetValue(full, out var expectedHash))
        {
            return IsCanaryFileIntactOnDisk(full);
        }

        try
        {
            var actual = SignatureVerifier.ComputeSha256(full);
            return string.Equals(actual, expectedHash, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    public void RemoveCanaries()
    {
        foreach (var path in _canaryHashes.Keys.ToList())
        {
            try
            {
                if (File.Exists(path))
                {
                    File.SetAttributes(path, FileAttributes.Normal);
                    File.Delete(path);
                }
            }
            catch
            {
                // Ignore cleanup failure on locked files.
            }
        }

        _canaryHashes.Clear();
    }
}
