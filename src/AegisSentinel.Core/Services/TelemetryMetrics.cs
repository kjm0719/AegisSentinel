using System.Diagnostics;

namespace AegisSentinel.Core.Services;

public sealed record TelemetrySnapshot(
    long ProcessEvents,
    long FileEvents,
    long NetworkEvents,
    long DnsEvents,
    long RegistryEvents,
    long ThreatsDetected,
    long ProcessesFrozen,
    long CustomRuleHits,
    double AverageEvalMicroseconds,
    TimeSpan Uptime)
{
    public long TotalTelemetryEvents => ProcessEvents + FileEvents + NetworkEvents + DnsEvents + RegistryEvents;
}

/// <summary>
/// Lock-free (Interlocked) real-time telemetry and latency instrumentation for AegisSentinel EDR.
/// Enables empirical performance benchmarking and SOC operational health visibility with zero lock contention.
/// </summary>
public sealed class TelemetryMetrics
{
    private readonly DateTimeOffset _startedAtUtc = DateTimeOffset.UtcNow;
    private long _processEvents;
    private long _fileEvents;
    private long _networkEvents;
    private long _dnsEvents;
    private long _registryEvents;
    private long _threatsDetected;
    private long _processesFrozen;
    private long _customRuleHits;
    private long _totalEvalTicks;
    private long _totalEvalCount;

    public void IncrementProcessEvent() => Interlocked.Increment(ref _processEvents);
    public void IncrementFileEvent() => Interlocked.Increment(ref _fileEvents);
    public void IncrementNetworkEvent() => Interlocked.Increment(ref _networkEvents);
    public void IncrementDnsEvent() => Interlocked.Increment(ref _dnsEvents);
    public void IncrementRegistryEvent() => Interlocked.Increment(ref _registryEvents);
    public void IncrementThreatDetected() => Interlocked.Increment(ref _threatsDetected);
    public void IncrementProcessFrozen() => Interlocked.Increment(ref _processesFrozen);
    public void IncrementCustomRuleHit() => Interlocked.Increment(ref _customRuleHits);

    public void RecordEvaluationTicks(long stopwatchTicks)
    {
        if (stopwatchTicks < 0) return;
        Interlocked.Add(ref _totalEvalTicks, stopwatchTicks);
        Interlocked.Increment(ref _totalEvalCount);
    }

    public TelemetrySnapshot GetSnapshot()
    {
        long count = Interlocked.Read(ref _totalEvalCount);
        long ticks = Interlocked.Read(ref _totalEvalTicks);
        double avgMicros = count > 0
            ? (ticks * 1_000_000.0 / Stopwatch.Frequency) / count
            : 0.0;

        return new TelemetrySnapshot(
            Interlocked.Read(ref _processEvents),
            Interlocked.Read(ref _fileEvents),
            Interlocked.Read(ref _networkEvents),
            Interlocked.Read(ref _dnsEvents),
            Interlocked.Read(ref _registryEvents),
            Interlocked.Read(ref _threatsDetected),
            Interlocked.Read(ref _processesFrozen),
            Interlocked.Read(ref _customRuleHits),
            Math.Round(avgMicros, 2),
            DateTimeOffset.UtcNow - _startedAtUtc);
    }
}
