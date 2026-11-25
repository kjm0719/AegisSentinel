using System.Security.Cryptography;
using System.Text;

namespace AegisSentinel.Core.Services;

/// <summary>
/// Seals AegisSentinel configuration files with an HMAC-SHA256 tag whose secret key is protected
/// via Windows DPAPI (CurrentUser), preventing malware from silently modifying policy.json
/// to disable protection or inject itself into whitelists.
/// </summary>
public sealed class PolicyIntegritySigner
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("AegisSentinel-SelfDefense-HMAC-v4");
    private readonly string _keyFilePath;
    private readonly string _registryWitnessValueName;
    private readonly object _keySync = new();
    private byte[]? _cachedKey;

    public PolicyIntegritySigner(string baseDirectory)
    {
        Directory.CreateDirectory(baseDirectory);
        _keyFilePath = Path.Combine(baseDirectory, ".aegis_seal.key");
        var dirHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Path.GetFullPath(baseDirectory).ToLowerInvariant())))[..16];
        _registryWitnessValueName = $"SealInit_{dirHash}";
    }

    public void SignFile(string filePath)
    {
        if (!File.Exists(filePath)) return;
        var key = GetOrCreateKey();
        var payload = File.ReadAllBytes(filePath);
        var tag = HMACSHA256.HashData(key, payload);
        var hmacPath = filePath + ".hmac";
        if (File.Exists(hmacPath))
        {
            try { File.SetAttributes(hmacPath, FileAttributes.Normal); } catch { }
        }
        File.WriteAllText(hmacPath, Convert.ToHexString(tag));
        RecordSealWitness();
    }

    public bool VerifyFile(string filePath, out string reason)
    {
        reason = string.Empty;
        if (!File.Exists(filePath))
        {
            reason = "정책 파일이 삭제되었습니다.";
            return false;
        }

        var sigPath = filePath + ".hmac";
        if (!File.Exists(sigPath))
        {
            // SECURITY CRITICAL: If the DPAPI seal key OR registry witness already exists, this directory was previously sealed —
            // deleting both .hmac and .aegis_seal.key CANNOT bypass integrity verification!
            if (File.Exists(_keyFilePath) || _cachedKey is not null || HasSealWitness())
            {
                reason = "정책 무결성 서명 파일(.hmac)이 무단 삭제되었습니다 (자가 방어 변조 탐지).";
                return false;
            }

            // Genuine first-time migration before any seal key has ever been created
            reason = "HMAC 서명 파일 없음 (초기 마이그레이션)";
            return true;
        }

        try
        {
            if (!TryLoadExistingKey(out var key))
            {
                reason = "무결성 봉인 키(.aegis_seal.key)가 삭제되었거나 손상되었습니다 (자가 방어 변조 탐지).";
                return false;
            }
            var payload = File.ReadAllBytes(filePath);
            var expectedHex = File.ReadAllText(sigPath).Trim();
            var actualBytes = HMACSHA256.HashData(key, payload);
            var expectedBytes = Convert.FromHexString(expectedHex);

            if (!CryptographicOperations.FixedTimeEquals(actualBytes, expectedBytes))
            {
                reason = "정책 파일의 HMAC-SHA256 무결성 서명이 일치하지 않습니다 (외부 무단 변조 의심).";
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            reason = $"서명 검증 오류: {ex.Message}";
            return false;
        }
    }

    private const string SecretPrefix = "dpapi:";

    /// <summary>
    /// Encrypts sensitive policy secrets (e.g. API keys) at rest using Windows DPAPI (CurrentUser)
    /// so policy.json never exposes plaintext credentials on disk.
    /// </summary>
    public static string ProtectSecret(string? plainText)
    {
        if (string.IsNullOrWhiteSpace(plainText)) return string.Empty;
        var trimmed = plainText.Trim();
        if (trimmed.StartsWith(SecretPrefix, StringComparison.Ordinal)) return trimmed;
        try
        {
            var raw = Encoding.UTF8.GetBytes(trimmed);
            var cipher = ProtectedData.Protect(raw, Entropy, DataProtectionScope.CurrentUser);
            return SecretPrefix + Convert.ToBase64String(cipher);
        }
        catch
        {
            return trimmed;
        }
    }

    public static string UnprotectSecret(string? storedValue)
    {
        if (string.IsNullOrWhiteSpace(storedValue)) return string.Empty;
        var trimmed = storedValue.Trim();
        if (!trimmed.StartsWith(SecretPrefix, StringComparison.Ordinal)) return trimmed;
        try
        {
            var cipher = Convert.FromBase64String(trimmed[SecretPrefix.Length..]);
            var plain = ProtectedData.Unprotect(cipher, Entropy, DataProtectionScope.CurrentUser);
            return Encoding.UTF8.GetString(plain);
        }
        catch
        {
            return string.Empty;
        }
    }

    private bool TryLoadExistingKey(out byte[] key)
    {
        lock (_keySync)
        {
            if (_cachedKey is not null)
            {
                key = _cachedKey;
                return true;
            }

            if (File.Exists(_keyFilePath))
            {
                try
                {
                    var protectedBytes = File.ReadAllBytes(_keyFilePath);
                    _cachedKey = ProtectedData.Unprotect(protectedBytes, Entropy, DataProtectionScope.CurrentUser);
                    key = _cachedKey;
                    return true;
                }
                catch { }
            }

            key = Array.Empty<byte>();
            return false;
        }
    }

    private void RecordSealWitness()
    {
        try
        {
            using var k = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\AegisSentinel\IntegrityWitness");
            k?.SetValue(_registryWitnessValueName, 1, Microsoft.Win32.RegistryValueKind.DWord);
        }
        catch { }
    }

    private bool HasSealWitness()
    {
        try
        {
            using var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\AegisSentinel\IntegrityWitness");
            return k?.GetValue(_registryWitnessValueName) is int v && v == 1;
        }
        catch
        {
            return false;
        }
    }

    private byte[] GetOrCreateKey()
    {
        lock (_keySync)
        {
            if (_cachedKey is not null) return _cachedKey;

            if (File.Exists(_keyFilePath))
            {
                try
                {
                    var protectedBytes = File.ReadAllBytes(_keyFilePath);
                    _cachedKey = ProtectedData.Unprotect(protectedBytes, Entropy, DataProtectionScope.CurrentUser);
                    return _cachedKey;
                }
                catch
                {
                    // Regenerate key if unreadable on another profile
                }
            }

            var newKey = RandomNumberGenerator.GetBytes(32);
            var sealedBytes = ProtectedData.Protect(newKey, Entropy, DataProtectionScope.CurrentUser);
            if (File.Exists(_keyFilePath))
            {
                try
                {
                    File.SetAttributes(_keyFilePath, FileAttributes.Normal);
                    File.Delete(_keyFilePath);
                }
                catch { }
            }
            File.WriteAllBytes(_keyFilePath, sealedBytes);
            try { File.SetAttributes(_keyFilePath, FileAttributes.Hidden); } catch { }
            _cachedKey = newKey;
            return _cachedKey;
        }
    }
}
