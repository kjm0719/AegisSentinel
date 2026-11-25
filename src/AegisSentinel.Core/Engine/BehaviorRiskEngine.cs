using System.Collections.Concurrent;
using AegisSentinel.Core.Models;

namespace AegisSentinel.Core.Engine;

public sealed record RiskAssessment(
    int TotalScore,
    IReadOnlyList<string> Signals,
    bool IsExfiltrationChain,
    bool ShouldFreezeProcess,
    bool ShouldPromptUser);

/// <summary>
/// Correlates multiple weak and strong behavioral signals per PID over a sliding 10-minute window.
/// Enables low-friction operation: harmless single signals stay quiet while true attack chains escalate immediately.
/// </summary>
public sealed class BehaviorRiskEngine
{
    private sealed class ProcessRiskState
    {
        public readonly object Sync = new();
        public readonly List<(DateTimeOffset Time, string Signal, int Weight)> Entries = new();
        public DateTimeOffset? LastCredentialAccess;
        public DateTimeOffset? LastExternalNetwork;
    }

    private readonly ConcurrentDictionary<int, ProcessRiskState> _states = new();

    public RiskAssessment RecordSignal(
        int pid,
        string signalName,
        int weight,
        bool marksCredentialAccess = false,
        bool marksExternalNetwork = false,
        bool smartLowFrictionMode = true,
        DateTimeOffset? nowOverride = null)
    {
        var now = nowOverride ?? DateTimeOffset.UtcNow;
        if (pid <= 4)
        {
            return new RiskAssessment(
                Math.Clamp(weight, 0, 100),
                new[] { $"{signalName}(+{weight})" },
                IsExfiltrationChain: false,
                ShouldFreezeProcess: false,
                ShouldPromptUser: weight >= 75);
        }

        var state = _states.GetOrAdd(pid, _ => new ProcessRiskState());
        if (_states.Count > 2048)
        {
            PruneStaleStates(now);
        }
        bool isExfilChain;
        int totalScore;
        List<string> signals;

        lock (state.Sync)
        {
            var cutoff = now.AddMinutes(-10);
            state.Entries.RemoveAll(e => e.Time < cutoff);

            // Never stack the exact same signal name on the same PID; refresh timestamp and keep max weight.
            // Only DISTINCT behavioral signals (e.g. DropPath + CredentialAccess + ExternalNetwork) sum together!
            var existingIdx = state.Entries.FindIndex(e => e.Signal.Equals(signalName, StringComparison.OrdinalIgnoreCase));
            if (existingIdx >= 0)
            {
                var prev = state.Entries[existingIdx];
                state.Entries[existingIdx] = (now, signalName, Math.Max(prev.Weight, weight));
            }
            else
            {
                state.Entries.Add((now, signalName, weight));
            }

            if (marksCredentialAccess)
            {
                state.LastCredentialAccess = now;
            }

            if (marksExternalNetwork)
            {
                state.LastExternalNetwork = now;
            }

            bool activeCred = state.LastCredentialAccess.HasValue && state.LastCredentialAccess.Value >= cutoff;
            bool activeNet = state.LastExternalNetwork.HasValue && state.LastExternalNetwork.Value >= cutoff;
            isExfilChain = activeCred && activeNet;
            if (isExfilChain && !state.Entries.Any(e => e.Signal == "CredentialExfiltrationChain"))
            {
                state.Entries.Add((now, "CredentialExfiltrationChain", 45));
            }

            totalScore = Math.Min(100, state.Entries.Sum(e => e.Weight));
            signals = state.Entries.Select(e => $"{e.Signal}(+{e.Weight})").ToList();
        }

        bool freeze = smartLowFrictionMode ? totalScore >= 75 : totalScore >= 55;
        bool prompt = smartLowFrictionMode ? totalScore >= 75 : totalScore >= 50;

        return new RiskAssessment(totalScore, signals, isExfilChain, freeze, prompt);
    }

    public int GetCurrentScore(int pid)
    {
        if (!_states.TryGetValue(pid, out var state))
        {
            return 0;
        }

        var cutoff = DateTimeOffset.UtcNow.AddMinutes(-10);
        lock (state.Sync)
        {
            state.Entries.RemoveAll(e => e.Time < cutoff);
            return Math.Min(100, state.Entries.Sum(e => e.Weight));
        }
    }

    public RiskAssessment GetCurrentAssessment(
        int pid,
        int fallbackScore,
        IReadOnlyList<string> fallbackSignals,
        bool smartLowFrictionMode = true)
    {
        if (pid <= 4 || !_states.TryGetValue(pid, out var state))
        {
            int score = Math.Clamp(fallbackScore, 0, 100);
            bool freezeFallback = smartLowFrictionMode ? score >= 75 : score >= 55;
            bool promptFallback = smartLowFrictionMode ? score >= 75 : score >= 50;
            return new RiskAssessment(score, fallbackSignals, false, freezeFallback, promptFallback);
        }

        int totalScore;
        List<string> signals;
        bool isExfilChain;
        var cutoff = DateTimeOffset.UtcNow.AddMinutes(-10);
        lock (state.Sync)
        {
            state.Entries.RemoveAll(e => e.Time < cutoff);
            totalScore = Math.Max(fallbackScore, Math.Min(100, state.Entries.Sum(e => e.Weight)));
            signals = state.Entries.Select(e => $"{e.Signal}(+{e.Weight})").ToList();
            isExfilChain = state.LastCredentialAccess >= cutoff && state.LastExternalNetwork >= cutoff;
        }

        bool freeze = smartLowFrictionMode ? totalScore >= 75 : totalScore >= 55;
        bool prompt = smartLowFrictionMode ? totalScore >= 75 : totalScore >= 50;
        return new RiskAssessment(totalScore, signals, isExfilChain, freeze, prompt);
    }

    public bool HasAccessedCredentials(int pid)
    {
        if (!_states.TryGetValue(pid, out var state)) return false;
        var cutoff = DateTimeOffset.UtcNow.AddMinutes(-10);
        lock (state.Sync)
        {
            return state.LastCredentialAccess.HasValue && state.LastCredentialAccess.Value >= cutoff;
        }
    }

    public IReadOnlyList<int> GetTrackedPids()
    {
        return _states.Keys.ToList();
    }

    public void ClearProcess(int pid)
    {
        _states.TryRemove(pid, out _);
    }

    private void PruneStaleStates(DateTimeOffset now)
    {
        var cutoff = now.AddMinutes(-15);
        foreach (var kvp in _states)
        {
            bool isEmpty;
            lock (kvp.Value.Sync)
            {
                kvp.Value.Entries.RemoveAll(e => e.Time < cutoff);
                isEmpty = kvp.Value.Entries.Count == 0;
            }
            if (isEmpty)
            {
                _states.TryRemove(kvp.Key, out _);
            }
        }
    }
}
