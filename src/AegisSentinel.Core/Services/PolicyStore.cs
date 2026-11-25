using System.Text.Json;
using AegisSentinel.Core.Models;

namespace AegisSentinel.Core.Services;

public sealed class PolicyStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private readonly PolicyIntegritySigner _signer;
    private readonly object _fileSync = new();

    public string BaseDirectory { get; }
    public string PolicyFilePath => Path.Combine(BaseDirectory, "policy.json");
    public PolicyIntegritySigner Signer => _signer;
    public bool LastLoadDetectedTampering { get; private set; }
    public string LastTamperReason { get; private set; } = string.Empty;

    public PolicyStore(string? baseDirectory = null)
    {
        BaseDirectory = baseDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AegisSentinel");
        Directory.CreateDirectory(BaseDirectory);
        _signer = new PolicyIntegritySigner(BaseDirectory);
    }

    public bool VerifyIntegrity(out string reason)
    {
        lock (_fileSync)
        {
            return _signer.VerifyFile(PolicyFilePath, out reason);
        }
    }

    public GuardPolicy Load()
    {
        lock (_fileSync)
        {
            LastLoadDetectedTampering = false;
            LastTamperReason = string.Empty;

            try
            {
                if (File.Exists(PolicyFilePath))
                {
                    if (!_signer.VerifyFile(PolicyFilePath, out var reason))
                    {
                        LastLoadDetectedTampering = true;
                        LastTamperReason = reason;
                        // Reject tampered policy on disk and restore safe hardened defaults!
                        var safeDefault = GuardPolicy.CreateDefault();
                        try { SaveLocked(safeDefault); } catch { }
                        return safeDefault;
                    }

                    var json = File.ReadAllText(PolicyFilePath);
                    var policy = JsonSerializer.Deserialize<GuardPolicy>(json, JsonOptions);
                    if (policy is not null)
                    {
                        policy.VirusTotalApiKey = PolicyIntegritySigner.UnprotectSecret(policy.VirusTotalApiKey);
                        policy.SanitizeAndValidate();
                        if (!File.Exists(PolicyFilePath + ".hmac"))
                        {
                            _signer.SignFile(PolicyFilePath);
                        }
                        return policy;
                    }
                }
            }
            catch
            {
                // Fall back to default policy if file is corrupted.
            }

            var defaultPolicy = GuardPolicy.CreateDefault();
            try { SaveLocked(defaultPolicy); } catch { }
            return defaultPolicy;
        }
    }

    public void Save(GuardPolicy policy)
    {
        lock (_fileSync)
        {
            policy.SanitizeAndValidate();
            SaveLocked(policy);
        }
    }

    private void SaveLocked(GuardPolicy policy)
    {
        Directory.CreateDirectory(BaseDirectory);
        var toPersist = policy.Clone();
        toPersist.SanitizeAndValidate();
        // Encrypt API key at rest via Windows DPAPI so policy.json never holds plaintext secrets
        toPersist.VirusTotalApiKey = PolicyIntegritySigner.ProtectSecret(toPersist.VirusTotalApiKey);
        var json = JsonSerializer.Serialize(toPersist, JsonOptions);
        var tmp = PolicyFilePath + $".{Guid.NewGuid():N}.tmp";
        File.WriteAllText(tmp, json);
        if (File.Exists(PolicyFilePath))
        {
            try { File.SetAttributes(PolicyFilePath, FileAttributes.Normal); } catch { }
        }
        File.Move(tmp, PolicyFilePath, overwrite: true);
        _signer.SignFile(PolicyFilePath);
    }
}
