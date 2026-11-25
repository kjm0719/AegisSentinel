using System.Runtime.InteropServices;
using AegisSentinel.Core.Models;

namespace AegisSentinel.Core.Engine;

/// <summary>
/// Hidden NTFS Alternate Data Stream (ADS) Detector using Win32 FindFirstStreamW / FindNextStreamW.
/// Catches attackers hiding executables, scripts, or payloads inside innocent files
/// (e.g. "notes.txt:dropper.exe" or "invoice.pdf:payload.ps1") which are invisible in Windows Explorer.
/// </summary>
public static class NtfsAdsScanner
{
    private static readonly HashSet<string> BenignKnownStreamNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "::$DATA",
        ":Zone.Identifier:$DATA",
        ":SmartScreen:$DATA",
        ":encryptable:$DATA",
        ":favicon:$DATA",
        ":OECustomProperty:$DATA",
        ":com.dropbox.attrs:$DATA",
        ":com.dropbox.attributes:$DATA",
        ":OneDrive.SyncId:$DATA",
        ":WofCompressedData:$DATA",
        ":AFP_AfpInfo:$DATA",
        ":AFP_Resource:$DATA",
        ":SummaryInformation:$DATA",
        ":DocumentSummaryInformation:$DATA",
        ":Sebek:$DATA"
    };

    private static readonly HashSet<string> DangerousAdsExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".jse", ".vbe", ".wsf", ".lnk", ".msi", ".bin", ".dat", ".zip"
    };

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WIN32_FIND_STREAM_DATA
    {
        public long StreamSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
        public string cStreamName;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr FindFirstStreamW(
        string lpFileName,
        int InfoLevel, // 0 = FindStreamInfoStandard
        out WIN32_FIND_STREAM_DATA lpFindStreamData,
        uint dwFlags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FindNextStreamW(
        IntPtr hFindStream,
        out WIN32_FIND_STREAM_DATA lpFindStreamData);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FindClose(IntPtr hFindFile);

    private static readonly IntPtr InvalidHandleValue = new(-1);

    /// <summary>
    /// Enumerates non-default NTFS Alternate Data Streams on a file and detects hidden executables/scripts/PE headers.
    /// </summary>
    public static List<MalwareThreatItem> InspectFileStreams(string filePath)
    {
        var results = new List<MalwareThreatItem>();
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath)) return results;

        var handle = FindFirstStreamW(filePath, 0, out var data, 0);
        if (handle == IntPtr.Zero || handle == InvalidHandleValue) return results;

        try
        {
            do
            {
                var streamName = data.cStreamName;
                if (string.IsNullOrWhiteSpace(streamName) || BenignKnownStreamNames.Contains(streamName))
                {
                    continue;
                }

                // Only inspect alternate $DATA streams (never NTFS internal ::$EA / ::$INDEX_ALLOCATION / ::$BITMAP attributes!)
                if (!streamName.EndsWith(":$DATA", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                // Strip leading ':' and trailing ':$DATA'
                var cleanName = streamName.TrimStart(':')[..^6];
                if (string.IsNullOrWhiteSpace(cleanName) ||
                    cleanName.StartsWith("$", StringComparison.Ordinal) ||
                    cleanName.StartsWith("com.dropbox", StringComparison.OrdinalIgnoreCase) ||
                    cleanName.StartsWith("com.apple.", StringComparison.OrdinalIgnoreCase) ||
                    cleanName.StartsWith("ms-", StringComparison.OrdinalIgnoreCase) ||
                    cleanName.StartsWith("Win32App_", StringComparison.OrdinalIgnoreCase) ||
                    cleanName.StartsWith("{", StringComparison.Ordinal))
                {
                    continue;
                }

                var adsFullPath = $"{filePath}:{cleanName}";
                var adsExt = Path.GetExtension(cleanName);
                bool hasDangerousExt = !string.IsNullOrEmpty(adsExt) && DangerousAdsExtensions.Contains(adsExt);
                bool hasPeHeader = false;

                if (data.StreamSize >= 64 && data.StreamSize <= 25 * 1024 * 1024)
                {
                    try
                    {
                        using var fs = new FileStream(adsFullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                        var head = new byte[Math.Min(1024, (int)data.StreamSize)];
                        int read = fs.Read(head, 0, head.Length);
                        hasPeHeader = PolyglotAndMagicSniffer.HasValidPeHeader(head.AsSpan(0, read));
                    }
                    catch { }
                }

                if (hasPeHeader || hasDangerousExt || data.StreamSize >= 64 * 1024)
                {
                    results.Add(new MalwareThreatItem
                    {
                        Stage = MalwareScanStage.VirusSignatureAndFile,
                        ThreatName = hasPeHeader ? "Trojan.NTFS.HiddenAdsExecutable" : "Suspicious.NTFS.AlternateDataStream",
                        CategoryLabel = "NTFS 숨김 스트림(ADS) 페이로드",
                        Severity = (hasPeHeader || hasDangerousExt) ? ThreatSeverity.Critical : ThreatSeverity.High,
                        RiskScore = hasPeHeader ? 96 : (hasDangerousExt ? 88 : 70),
                        TargetPath = adsFullPath,
                        EntryName = $"{Path.GetFileName(filePath)}:{cleanName}",
                        SignatureLabel = $"ADS 크기 {data.StreamSize:N0} bytes",
                        Description = hasPeHeader
                            ? $"탐색기에 보이지 않는 NTFS 숨김 스트림(ADS) 내부에 Windows PE 실행파일이 은닉되어 있습니다: {adsFullPath} (원본 파일 보존 스트림 정밀 제거 지원)"
                            : $"파일에 숨겨진 NTFS 대체 데이터 스트림(ADS)이 탐지되었습니다: {cleanName} ({data.StreamSize:N0}B)",
                        ActionType = (hasPeHeader || hasDangerousExt)
                            ? RemediationActionType.RemoveAlternateDataStream
                            : RemediationActionType.ManualReview,
                        RecommendedForCure = hasPeHeader || hasDangerousExt
                    });
                }
            }
            while (FindNextStreamW(handle, out data));
        }
        finally
        {
            FindClose(handle);
        }

        return results;
    }

    public static List<MalwareThreatItem> ScanDirectoryTopLevel(string directory, int maxFiles, CancellationToken ct)
    {
        var results = new List<MalwareThreatItem>();
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory)) return results;

        try
        {
            var opts = new System.IO.EnumerationOptions
            {
                RecurseSubdirectories = true,
                MaxRecursionDepth = 3,
                IgnoreInaccessible = true,
                AttributesToSkip = FileAttributes.ReparsePoint
            };

            int checkedCount = 0;
            foreach (var file in Directory.EnumerateFiles(directory, "*", opts))
            {
                ct.ThrowIfCancellationRequested();
                if (file.Contains(@"\node_modules\", StringComparison.OrdinalIgnoreCase) ||
                    file.Contains(@"\.git\", StringComparison.OrdinalIgnoreCase) ||
                    file.Contains(@"\AegisSentinel\Quarantine\", StringComparison.OrdinalIgnoreCase) ||
                    file.Contains(@"\AegisSentinel\RemediationBackups\", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                if (++checkedCount > maxFiles) break;
                var hits = InspectFileStreams(file);
                if (hits.Count > 0) results.AddRange(hits);
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }

        return results;
    }
}
