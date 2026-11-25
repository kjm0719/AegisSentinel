using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AegisSentinel.Core.Models;
using AegisSentinel.Core.Native;

namespace AegisSentinel.Core.Services;

public sealed class SignatureVerifier
{
    private readonly ConcurrentDictionary<string, (DateTime LastWriteUtc, long FileLength, SignatureInfo Info)> _cache =
        new(StringComparer.OrdinalIgnoreCase);

    private static readonly ConcurrentDictionary<string, (DateTime LastWriteUtc, long FileLength, string Sha256)> Sha256Cache =
        new(StringComparer.OrdinalIgnoreCase);

    public SignatureInfo VerifyFile(string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            return new SignatureInfo(SignatureStatus.Unknown, string.Empty, ErrorMessage: "File not found");
        }

        try
        {
            var fullPath = Path.GetFullPath(filePath);
            if (!File.Exists(fullPath))
            {
                return new SignatureInfo(SignatureStatus.Unknown, string.Empty, ErrorMessage: "File not found");
            }

            var fi = new FileInfo(fullPath);
            var lastWriteUtc = fi.LastWriteTimeUtc;
            var fileLength = fi.Length;
            if (_cache.TryGetValue(fullPath, out var cached) &&
                cached.LastWriteUtc == lastWriteUtc &&
                cached.FileLength == fileLength)
            {
                return cached.Info;
            }

            var result = VerifyInternal(fullPath);
            if (_cache.Count > 4096)
            {
                _cache.Clear();
            }

            _cache[fullPath] = (lastWriteUtc, fileLength, result);
            return result;
        }
        catch (Exception ex)
        {
            return new SignatureInfo(SignatureStatus.Unknown, string.Empty, ErrorMessage: ex.Message);
        }
    }

    public static string ComputeSha256(string filePath)
    {
        using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var hash = SHA256.HashData(stream);
        return Convert.ToHexString(hash);
    }

    public static string ComputeSha256Cached(string filePath)
    {
        var fullPath = Path.GetFullPath(filePath);
        var fi = new FileInfo(fullPath);
        var lastWrite = fi.LastWriteTimeUtc;
        var len = fi.Length;
        if (Sha256Cache.TryGetValue(fullPath, out var cached) &&
            cached.LastWriteUtc == lastWrite &&
            cached.FileLength == len)
        {
            return cached.Sha256;
        }

        var sha = ComputeSha256(fullPath);
        if (Sha256Cache.Count > 4096) Sha256Cache.Clear();
        Sha256Cache[fullPath] = (lastWrite, len, sha);
        return sha;
    }

    private static SignatureInfo VerifyInternal(string filePath)
    {
        const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
        const int CERT_E_CHAINING = unchecked((int)0x800B010A);
        const int TRUST_E_BAD_DIGEST = unchecked((int)0x80096010);
        const int CERT_E_REVOKED = unchecked((int)0x800B010C);
        const int TRUST_E_EXPLICIT_DISTRUST = unchecked((int)0x800B0111);
        const int TRUST_E_SUBJECT_NOT_TRUSTED = unchecked((int)0x800B0004);
        const int CRYPT_E_SECURITY_SETTINGS = unchecked((int)0x80092026);

        var trustStatus = VerifyWinTrust(filePath, cacheOnlyUrlRetrieval: true, out var winTrustError);
        var (publisher, thumbprint) = ExtractPublisherInfo(filePath);

        // If embedded cert failed ONLY due to offline AIA intermediate cache miss (CERT_E_CHAINING), retry once with AIA allowed
        if (trustStatus == CERT_E_CHAINING && !string.IsNullOrWhiteSpace(publisher))
        {
            var retryStatus = VerifyWinTrust(filePath, cacheOnlyUrlRetrieval: false, out var retryErr);
            if (retryStatus == 0)
            {
                trustStatus = 0;
                winTrustError = retryErr;
            }
        }

        if (trustStatus == 0)
        {
            var isMicrosoft = publisher.Contains("Microsoft", StringComparison.OrdinalIgnoreCase);
            return new SignatureInfo(
                isMicrosoft ? SignatureStatus.TrustedMicrosoft : SignatureStatus.TrustedVendor,
                string.IsNullOrWhiteSpace(publisher) ? "Verified Publisher" : publisher,
                thumbprint);
        }

        if (trustStatus == TRUST_E_NOSIGNATURE)
        {
            // Cryptographically verify Windows Security Catalog (.cat) signatures (e.g. explorer.exe, SystemApps, WindowsApps, System32, WHQL drivers)
            // instead of blindly trusting any unsigned file placed in System32!
            if (TryVerifyCatalogSignature(filePath, out var catPublisher, out var catThumbprint))
            {
                bool catIsMs = catPublisher.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) ||
                               string.IsNullOrWhiteSpace(catPublisher);
                return new SignatureInfo(
                    catIsMs ? SignatureStatus.TrustedMicrosoft : SignatureStatus.TrustedVendor,
                    string.IsNullOrWhiteSpace(catPublisher) ? "Microsoft Windows (Catalog Verified)" : catPublisher,
                    catThumbprint);
            }

            return new SignatureInfo(SignatureStatus.Unsigned, string.Empty);
        }

        // Only classify actual cryptographic digest tampering or explicit revocation/distrust as InvalidOrTampered.
        bool isTrueTamperOrRevoked =
            trustStatus == TRUST_E_BAD_DIGEST ||
            trustStatus == CERT_E_REVOKED ||
            trustStatus == TRUST_E_EXPLICIT_DISTRUST ||
            trustStatus == TRUST_E_SUBJECT_NOT_TRUSTED ||
            trustStatus == CRYPT_E_SECURITY_SETTINGS;

        if (!isTrueTamperOrRevoked)
        {
            if (filePath.Contains(@"\ProgramData\Microsoft\Windows Defender\", StringComparison.OrdinalIgnoreCase) &&
                publisher.Contains("Microsoft", StringComparison.OrdinalIgnoreCase))
            {
                return new SignatureInfo(SignatureStatus.TrustedMicrosoft, publisher, thumbprint);
            }

            return new SignatureInfo(
                SignatureStatus.Unsigned,
                publisher,
                thumbprint,
                $"WinVerifyTrust=0x{trustStatus:X8}{(string.IsNullOrEmpty(winTrustError) ? "" : $" ({winTrustError})")}");
        }

        return new SignatureInfo(
            SignatureStatus.InvalidOrTampered,
            publisher,
            thumbprint,
            $"WinVerifyTrust=0x{trustStatus:X8}{(string.IsNullOrEmpty(winTrustError) ? "" : $" ({winTrustError})")}");
    }

    private static bool TryVerifyCatalogSignature(string filePath, out string publisher, out string thumbprint)
    {
        publisher = string.Empty;
        thumbprint = string.Empty;

        IntPtr hCatAdmin = IntPtr.Zero;
        if (!NativeMethods.CryptCATAdminAcquireContext2(out hCatAdmin, IntPtr.Zero, null, IntPtr.Zero, 0) &&
            !NativeMethods.CryptCATAdminAcquireContext2(out hCatAdmin, IntPtr.Zero, "SHA256", IntPtr.Zero, 0))
        {
            return false;
        }

        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var hFile = fs.SafeFileHandle.DangerousGetHandle();

            uint hashLen = 0;
            if (!NativeMethods.CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref hashLen, null, 0) || hashLen == 0 || hashLen > 128)
            {
                return false;
            }

            var hashBytes = new byte[hashLen];
            if (!NativeMethods.CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref hashLen, hashBytes, 0))
            {
                return false;
            }

            var memberTag = Convert.ToHexString(hashBytes, 0, (int)hashLen);
            IntPtr hCatInfo = IntPtr.Zero;
            while (true)
            {
                hCatInfo = NativeMethods.CryptCATAdminEnumCatalogFromHash(hCatAdmin, hashBytes, hashLen, 0, ref hCatInfo);
                if (hCatInfo == IntPtr.Zero) break;

                try
                {
                    var catInfo = new NativeMethods.CATALOG_INFO
                    {
                        cbStruct = (uint)Marshal.SizeOf<NativeMethods.CATALOG_INFO>(),
                        wszCatalogFile = string.Empty
                    };
                    if (!NativeMethods.CryptCATCatalogInfoFromContext(hCatInfo, ref catInfo, 0) ||
                        string.IsNullOrWhiteSpace(catInfo.wszCatalogFile))
                    {
                        continue;
                    }

                    if (VerifyCatalogMemberWinTrust(catInfo.wszCatalogFile, filePath, memberTag, hFile, hashBytes, hashLen, hCatAdmin))
                    {
                        (publisher, thumbprint) = ExtractPublisherInfo(catInfo.wszCatalogFile);
                        NativeMethods.CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                        return true;
                    }
                }
                finally
                {
                    // Note: CryptCATAdminEnumCatalogFromHash automatically frees the previous context when advancing;
                    // if we break early on success, explicitly release the current context!
                }
            }

            return false;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (hCatAdmin != IntPtr.Zero)
            {
                NativeMethods.CryptCATAdminReleaseContext(hCatAdmin, 0);
            }
        }
    }

    private static bool VerifyCatalogMemberWinTrust(
        string catalogPath,
        string memberFilePath,
        string memberTag,
        IntPtr hMemberFile,
        byte[] hashBytes,
        uint hashLen,
        IntPtr hCatAdmin)
    {
        var hashHandle = GCHandle.Alloc(hashBytes, GCHandleType.Pinned);
        var catPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NativeMethods.WINTRUST_CATALOG_INFO>());
        bool initialized = false;
        try
        {
            var wtCat = new NativeMethods.WINTRUST_CATALOG_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<NativeMethods.WINTRUST_CATALOG_INFO>(),
                dwCatalogVersion = 0,
                pcwszCatalogFilePath = catalogPath,
                pcwszMemberTag = memberTag,
                pcwszMemberFilePath = memberFilePath,
                hMemberFile = hMemberFile,
                pbCalculatedFileHash = hashHandle.AddrOfPinnedObject(),
                cbCalculatedFileHash = hashLen,
                pcCatalogContext = IntPtr.Zero,
                hCatAdmin = hCatAdmin
            };
            Marshal.StructureToPtr(wtCat, catPtr, false);
            initialized = true;

            var trustData = new NativeMethods.WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<NativeMethods.WINTRUST_DATA>(),
                dwUIChoice = NativeMethods.WTD_UI_NONE,
                fdwRevocationChecks = NativeMethods.WTD_REVOKE_NONE,
                dwUnionChoice = NativeMethods.WTD_CHOICE_CATALOG,
                pFile = catPtr,
                dwStateAction = NativeMethods.WTD_STATEACTION_VERIFY,
                dwProvFlags = NativeMethods.WTD_CACHE_ONLY_URL_RETRIEVAL
            };

            var invalidHandle = new IntPtr(-1);
            try
            {
                return NativeMethods.WinVerifyTrust(invalidHandle, NativeMethods.WINTRUST_ACTION_GENERIC_VERIFY_V2, ref trustData) == 0;
            }
            finally
            {
                trustData.dwStateAction = NativeMethods.WTD_STATEACTION_CLOSE;
                _ = NativeMethods.WinVerifyTrust(invalidHandle, NativeMethods.WINTRUST_ACTION_GENERIC_VERIFY_V2, ref trustData);
            }
        }
        finally
        {
            if (initialized)
            {
                Marshal.DestroyStructure<NativeMethods.WINTRUST_CATALOG_INFO>(catPtr);
            }
            Marshal.FreeHGlobal(catPtr);
            hashHandle.Free();
        }
    }

    private static int VerifyWinTrust(string filePath, bool cacheOnlyUrlRetrieval, out string? errorMessage)
    {
        errorMessage = null;
        var fileInfo = new NativeMethods.WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<NativeMethods.WINTRUST_FILE_INFO>(),
            pcwszFilePath = filePath,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero
        };

        var fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NativeMethods.WINTRUST_FILE_INFO>());
        bool structureInitialized = false;
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);
            structureInitialized = true;

            uint provFlags = NativeMethods.WTD_SAFER_FLAG;
            if (cacheOnlyUrlRetrieval) provFlags |= NativeMethods.WTD_CACHE_ONLY_URL_RETRIEVAL;

            var trustData = new NativeMethods.WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<NativeMethods.WINTRUST_DATA>(),
                dwUIChoice = NativeMethods.WTD_UI_NONE,
                fdwRevocationChecks = NativeMethods.WTD_REVOKE_NONE,
                dwUnionChoice = NativeMethods.WTD_CHOICE_FILE,
                pFile = fileInfoPtr,
                dwStateAction = NativeMethods.WTD_STATEACTION_VERIFY,
                dwProvFlags = provFlags
            };

            var invalidHandle = new IntPtr(-1);
            try
            {
                return NativeMethods.WinVerifyTrust(invalidHandle, NativeMethods.WINTRUST_ACTION_GENERIC_VERIFY_V2, ref trustData);
            }
            finally
            {
                trustData.dwStateAction = NativeMethods.WTD_STATEACTION_CLOSE;
                _ = NativeMethods.WinVerifyTrust(invalidHandle, NativeMethods.WINTRUST_ACTION_GENERIC_VERIFY_V2, ref trustData);
            }
        }
        catch (Exception ex)
        {
            errorMessage = ex.Message;
            return -1;
        }
        finally
        {
            if (structureInitialized)
            {
                Marshal.DestroyStructure<NativeMethods.WINTRUST_FILE_INFO>(fileInfoPtr);
            }
            Marshal.FreeHGlobal(fileInfoPtr);
        }
    }

    private static (string Publisher, string Thumbprint) ExtractPublisherInfo(string filePath)
    {
        try
        {
#pragma warning disable SYSLIB0057 // CreateFromSignedFile parses PE Authenticode embedded certificate
            using var baseCert = X509Certificate.CreateFromSignedFile(filePath);
#pragma warning restore SYSLIB0057
            using var cert2 = new X509Certificate2(baseCert);
            var cn = cert2.GetNameInfo(X509NameType.SimpleName, false);
            return (cn ?? cert2.Subject, cert2.Thumbprint ?? string.Empty);
        }
        catch
        {
            return (string.Empty, string.Empty);
        }
    }
}
