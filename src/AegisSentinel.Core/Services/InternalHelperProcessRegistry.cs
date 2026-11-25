using System.Collections.Concurrent;

namespace AegisSentinel.Core.Services;

/// <summary>
/// Tracks PIDs of short-lived internal OS query helpers spawned by AegisSentinel itself
/// (e.g., Defender status, DNS cache, WFP netsh) so the engine never self-freezes its own queries
/// while still monitoring untrusted apps launched via SandboxLauncher.
/// </summary>
public static class InternalHelperProcessRegistry
{
    private static readonly ConcurrentDictionary<int, DateTimeOffset> HelperPids = new();
    private static int _activeSpawnScopes;

    /// <summary>
    /// Marks that AegisSentinel is currently inside Process.Start() for an internal OS helper,
    /// closing the sub-millisecond race window where ETW ProcessStart fires before Process.Start returns the child PID.
    /// </summary>
    public static void BeginSpawnScope() => Interlocked.Increment(ref _activeSpawnScopes);

    public static void EndSpawnScope()
    {
        if (Interlocked.Decrement(ref _activeSpawnScopes) < 0)
        {
            Interlocked.Exchange(ref _activeSpawnScopes, 0);
        }
    }

    public static void Register(int pid)
    {
        if (pid <= 4) return;
        HelperPids[pid] = DateTimeOffset.UtcNow;
        if (HelperPids.Count > 256)
        {
            var cutoff = DateTimeOffset.UtcNow.AddMinutes(-2);
            foreach (var kvp in HelperPids)
            {
                if (kvp.Value < cutoff) HelperPids.TryRemove(kvp.Key, out _);
            }
        }
    }

    public static void Unregister(int pid)
    {
        HelperPids.TryRemove(pid, out _);
    }

    public static bool IsInternalHelper(int pid, int parentPid = 0)
    {
        if (pid <= 4) return false;

        if (HelperPids.TryGetValue(pid, out var registeredAt))
        {
            if (DateTimeOffset.UtcNow - registeredAt <= TimeSpan.FromSeconds(30))
            {
                return true;
            }
            HelperPids.TryRemove(pid, out _);
        }

        if (parentPid == Environment.ProcessId && Volatile.Read(ref _activeSpawnScopes) > 0)
        {
            Register(pid);
            return true;
        }

        return false;
    }
}
