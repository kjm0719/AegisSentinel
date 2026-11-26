using System.Security.Cryptography;
using System.Text;
using AegisSentinel.Core.Engine;
using AegisSentinel.Core.Models;
using AegisSentinel.Core.Services;

namespace AegisSentinel.Tests;

/// <summary>
/// Regression tests for P1 growing-file boundary crossing, AEGISQ3 chunked authenticated AES-256-GCM,
/// cryptographic tamper/truncation/extension rejection, and accurate audit encryption-format reporting.
/// </summary>
public sealed class QuarantineChunkedAeadRegressionTests : IDisposable
{
    private readonly string _tempRoot;

    public QuarantineChunkedAeadRegressionTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), $"AegisChunkAead_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempRoot);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempRoot))
            {
                foreach (var f in Directory.EnumerateFiles(_tempRoot, "*", SearchOption.AllDirectories))
                {
                    try { File.SetAttributes(f, FileAttributes.Normal); } catch { }
                }
                Directory.Delete(_tempRoot, recursive: true);
            }
        }
        catch { }
    }

    [Fact]
    public void P1_LargeFileQuarantine_MustUseChunkedAesGcmNotFixedXor_AndAuditActualFormat()
    {
        var dir = Path.Combine(_tempRoot, "large_chunked_aead");
        Directory.CreateDirectory(dir);

        var target = Path.Combine(dir, "oversized_dropper.exe");
        var payload = RandomNumberGenerator.GetBytes(128 * 1024 + 37); // Non-aligned > 8 KiB test threshold
        File.WriteAllBytes(target, payload);

        var qm = new QuarantineManager(dir, maxInMemoryGcmBytes: 8 * 1024, chunkedGcmChunkSize: 16 * 1024);
        var store = new PolicyStore(dir);
        using var orch = new SecurityOrchestrator(store, quarantineManager: qm);

        var evt = new SecurityEvent
        {
            ProcessId = 0,
            Category = ThreatCategory.StaticMalware,
            Severity = ThreatSeverity.Critical,
            Title = "대용량 파일 격리 형식 검증",
            TargetPath = target
        };

        Assert.True(orch.KillAndQuarantine(evt));
        Assert.False(File.Exists(target));

        var entry = Assert.Single(qm.ListEntries());
        Assert.Equal(QuarantineManager.FormatAesGcmChunked, entry.EncryptionFormat);
        Assert.Contains(QuarantineManager.FormatAesGcmChunked, evt.ContainmentDetail);

        var header = new byte[8];
        using (var fs = File.OpenRead(entry.QuarantineFilePath))
        {
            Assert.Equal(8, fs.Read(header, 0, 8));
        }
        Assert.Equal("AEGISQ3\0", Encoding.ASCII.GetString(header));

        var restored = qm.RestoreFileDetailed(entry.Id);
        Assert.Equal(QuarantineRestoreStatus.Restored, restored.Status);
        Assert.Equal(payload, File.ReadAllBytes(target));
    }

    [Fact]
    public void P1_GrowingFileCrossingThresholdMidRead_MustSpillToChunkedAesGcmAndRestoreExactBytes()
    {
        var dir = Path.Combine(_tempRoot, "growing_file_spill");
        Directory.CreateDirectory(dir);

        // File starts at 3 KiB (BELOW the 4 KiB single-shot AES-GCM threshold),
        // then another writer appends 12 KiB mid-read so total becomes 15 KiB (ABOVE the 4 KiB threshold!).
        var target = Path.Combine(dir, "growing_dropper.exe");
        var initialPart = RandomNumberGenerator.GetBytes(3 * 1024);
        var appendedPart = RandomNumberGenerator.GetBytes(12 * 1024);
        var expectedFullBytes = new byte[initialPart.Length + appendedPart.Length];
        Buffer.BlockCopy(initialPart, 0, expectedFullBytes, 0, initialPart.Length);
        Buffer.BlockCopy(appendedPart, 0, expectedFullBytes, initialPart.Length, appendedPart.Length);

        File.WriteAllBytes(target, initialPart);

        bool appendedMidRead = false;
        var qm = new QuarantineManager(
            dir,
            maxInMemoryGcmBytes: 4 * 1024,
            chunkedGcmChunkSize: 4 * 1024,
            onAfterFirstReadChunkForTest: () =>
            {
                if (appendedMidRead) return;
                appendedMidRead = true;
                using var writer = new FileStream(target, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                writer.Write(appendedPart, 0, appendedPart.Length);
                writer.Flush(flushToDisk: true);
            });

        var entry = qm.QuarantineFile(target, "Growing file crossing boundary mid-read");
        Assert.True(appendedMidRead);
        Assert.False(File.Exists(target));
        Assert.Equal(QuarantineManager.FormatAesGcmChunked, entry.EncryptionFormat);
        Assert.Equal(expectedFullBytes.Length, entry.FileSize);

        // Verify header is AEGISQ3\0 (spilled safely from AEGISQ2 -> AEGISQ3)
        var header = new byte[8];
        using (var fs = File.OpenRead(entry.QuarantineFilePath))
        {
            Assert.Equal(8, fs.Read(header, 0, 8));
        }
        Assert.Equal("AEGISQ3\0", Encoding.ASCII.GetString(header));

        // Restoring with the SAME 4 KiB single-shot limit MUST succeed and return EVERY exact byte!
        var restoreRes = qm.RestoreFileDetailed(entry.Id);
        Assert.Equal(QuarantineRestoreStatus.Restored, restoreRes.Status);
        Assert.Equal(expectedFullBytes, File.ReadAllBytes(target));
    }

    [Fact]
    public void P1_ChunkedAesGcm_RejectsTamperTruncationAndExtension_AndHandlesZeroAndExactBoundarySizes()
    {
        // 1. Exact chunk boundary (2 * 4 KiB) + 0-byte empty file round-trip cleanly in AEGISQ3
        var dir = Path.Combine(_tempRoot, "aegisq3_edges");
        Directory.CreateDirectory(dir);
        var qm = new QuarantineManager(dir, maxInMemoryGcmBytes: 0, chunkedGcmChunkSize: 4096);

        var emptyTarget = Path.Combine(dir, "empty.exe");
        File.WriteAllBytes(emptyTarget, Array.Empty<byte>());
        var emptyEntry = qm.QuarantineFile(emptyTarget, "Empty AEGISQ3");
        Assert.Equal(QuarantineManager.FormatAesGcmChunked, emptyEntry.EncryptionFormat);
        Assert.Equal(QuarantineRestoreStatus.Restored, qm.RestoreFileDetailed(emptyEntry.Id).Status);
        Assert.Empty(File.ReadAllBytes(emptyTarget));

        var exactTarget = Path.Combine(dir, "exact_2chunks.exe");
        var exactBytes = RandomNumberGenerator.GetBytes(8192);
        File.WriteAllBytes(exactTarget, exactBytes);
        var exactEntry = qm.QuarantineFile(exactTarget, "Exact 2 chunks AEGISQ3");
        Assert.Equal(QuarantineRestoreStatus.Restored, qm.RestoreFileDetailed(exactEntry.Id).Status);
        Assert.Equal(exactBytes, File.ReadAllBytes(exactTarget));

        // 2. Cryptographic tamper, truncation, and trailing-byte extension MUST all fail IntegrityCheckFailed
        var tamperTarget = Path.Combine(dir, "tamper_check.exe");
        var tamperPayload = RandomNumberGenerator.GetBytes(10_000); // 3 chunks (4096 + 4096 + 1808)
        File.WriteAllBytes(tamperTarget, tamperPayload);
        var tamperEntry = qm.QuarantineFile(tamperTarget, "Tamper verification");
        var originalArtifact = File.ReadAllBytes(tamperEntry.QuarantineFilePath);

        // 2a. 1-bit flip in ciphertext
        var flipped = (byte[])originalArtifact.Clone();
        flipped[60] ^= 0x01;
        File.WriteAllBytes(tamperEntry.QuarantineFilePath, flipped);
        Assert.Equal(QuarantineRestoreStatus.IntegrityCheckFailed, qm.RestoreFileDetailed(tamperEntry.Id).Status);
        Assert.False(File.Exists(tamperTarget));

        // 2b. Truncate final chunk
        File.WriteAllBytes(tamperEntry.QuarantineFilePath, originalArtifact[..^100]);
        Assert.Equal(QuarantineRestoreStatus.IntegrityCheckFailed, qm.RestoreFileDetailed(tamperEntry.Id).Status);
        Assert.False(File.Exists(tamperTarget));

        // 2c. Append trailing garbage byte after final chunk
        var extended = new byte[originalArtifact.Length + 1];
        Buffer.BlockCopy(originalArtifact, 0, extended, 0, originalArtifact.Length);
        extended[^1] = 0xAA;
        File.WriteAllBytes(tamperEntry.QuarantineFilePath, extended);
        Assert.Equal(QuarantineRestoreStatus.IntegrityCheckFailed, qm.RestoreFileDetailed(tamperEntry.Id).Status);
        Assert.False(File.Exists(tamperTarget));

        // 2d. Restoring original untampered artifact succeeds cleanly
        File.WriteAllBytes(tamperEntry.QuarantineFilePath, originalArtifact);
        Assert.Equal(QuarantineRestoreStatus.Restored, qm.RestoreFileDetailed(tamperEntry.Id).Status);
        Assert.Equal(tamperPayload, File.ReadAllBytes(tamperTarget));
    }
}
