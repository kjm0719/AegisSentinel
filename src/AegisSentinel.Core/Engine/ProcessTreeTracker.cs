using System.Collections.Concurrent;
using AegisSentinel.Core.Models;

namespace AegisSentinel.Core.Engine;

public sealed record ProcessNode(
    int Pid,
    int ParentPid,
    string Name,
    string Path,
    string CommandLine,
    DateTimeOffset StartedAt);

/// <summary>
/// Tracks live multi-hop process genealogy (grandparent -> parent -> child) so chained
/// supply-chain attacks (e.g. launcher -> cmd -> powershell -> dropper) are traced to their root.
/// </summary>
public sealed class ProcessTreeTracker
{
    private readonly ConcurrentDictionary<int, ProcessNode> _nodes = new();

    public void RecordStart(int pid, int parentPid, string name, string path, string commandLine)
    {
        if (pid <= 4) return;
        var startedAt = DateTimeOffset.UtcNow;
        if (_nodes.TryGetValue(pid, out var existing) &&
            existing.ParentPid == parentPid &&
            string.Equals(existing.Path, path, StringComparison.OrdinalIgnoreCase))
        {
            startedAt = existing.StartedAt;
        }
        _nodes[pid] = new ProcessNode(pid, parentPid, name, path, commandLine, startedAt);
        if (_nodes.Count > 4096)
        {
            var cutoff = DateTimeOffset.UtcNow.AddHours(-6);
            foreach (var kvp in _nodes)
            {
                if (kvp.Value.StartedAt < cutoff)
                {
                    _nodes.TryRemove(kvp.Key, out _);
                }
            }
        }
    }

    public void RecordStop(int pid)
    {
        _nodes.TryRemove(pid, out _);
    }

    public IReadOnlyList<ProcessNode> GetAncestry(int pid, int maxDepth = 6)
    {
        var chain = new List<ProcessNode>();
        var visited = new HashSet<int>();
        int current = pid;

        for (int i = 0; i < maxDepth && current > 4; i++)
        {
            if (!visited.Add(current) || !_nodes.TryGetValue(current, out var node))
            {
                break;
            }

            if (chain.Count > 0 && chain[^1].StartedAt < node.StartedAt.AddSeconds(-2))
            {
                // Parent PID was recycled after the child started — stop walking recycled lineage
                break;
            }

            chain.Add(node);
            current = node.ParentPid;
        }

        chain.Reverse(); // Root ancestor -> ... -> current
        return chain;
    }

    public string FormatAncestryString(int pid)
    {
        var chain = GetAncestry(pid);
        if (chain.Count == 0)
        {
            return string.Empty;
        }

        return string.Join(" -> ", chain.Select(n => $"{n.Name}({n.Pid})"));
    }

    public ProcessNode? FindWatchedLauncherAncestor(int pid, GuardPolicy policy)
    {
        var chain = GetAncestry(pid);
        // Check all ancestors except the leaf process itself
        for (int i = 0; i < chain.Count - 1; i++)
        {
            var ancestor = chain[i];
            var baseName = Path.GetFileNameWithoutExtension(ancestor.Name);
            if (ProcessRuleEvaluator.IsWatchedLauncherOrRenderer(baseName, ancestor.Path, policy))
            {
                return ancestor;
            }
        }

        return null;
    }

    /// <summary>
    /// Finds all tracked descendant PIDs (children, grandchildren, etc.) spawned by rootPid
    /// so malicious process trees can be frozen or resumed atomically together.
    /// </summary>
    public IReadOnlyList<int> GetDescendantPids(int rootPid, int maxDepth = 5)
    {
        var result = new List<int>();
        if (rootPid <= 4) return result;

        var snapshot = _nodes.Values.ToList();
        var rootStart = _nodes.TryGetValue(rootPid, out var rootNode) ? rootNode.StartedAt : DateTimeOffset.MinValue;
        var visited = new HashSet<int> { rootPid };
        var frontier = new Queue<(int Pid, int Depth, DateTimeOffset ParentStart)>();
        frontier.Enqueue((rootPid, 0, rootStart));

        while (frontier.Count > 0)
        {
            var (currentPid, depth, parentStart) = frontier.Dequeue();
            if (depth >= maxDepth) continue;

            foreach (var node in snapshot)
            {
                if (node.ParentPid == currentPid &&
                    node.Pid > 4 &&
                    node.StartedAt >= parentStart.AddSeconds(-2) &&
                    visited.Add(node.Pid))
                {
                    result.Add(node.Pid);
                    frontier.Enqueue((node.Pid, depth + 1, node.StartedAt));
                }
            }
        }

        return result;
    }

    /// <summary>
    /// Returns tracked PIDs whose executable lives in a high-risk user-writable drop path
    /// so memory injection sweeps avoid enumerating all 250+ OS processes on battery.
    /// </summary>
    public IReadOnlyList<(int Pid, string Name, string Path)> GetHighRiskDropPathNodes()
    {
        var list = new List<(int, string, string)>();
        foreach (var kvp in _nodes)
        {
            var n = kvp.Value;
            if (n.Pid > 4 && !string.IsNullOrWhiteSpace(n.Path) && ProcessRuleEvaluator.IsHighRiskDropPath(n.Path))
            {
                list.Add((n.Pid, n.Name, n.Path));
            }
        }
        return list;
    }
}
