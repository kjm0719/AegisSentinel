using AegisSentinel.Core.Models;

namespace AegisSentinel.Core.Engine;

/// <summary>
/// Manages single-active-prompt + FIFO queueing for security intervention dialogs.
/// Guarantees that child-only suspended events are never stranded on queue saturation,
/// duplicate suppression, or shutdown, and merging duplicates never prematurely resumes
/// processes still managed by an active/queued prompt.
/// </summary>
public sealed class ThreatPromptQueueCoordinator
{
    private readonly int _maxQueuedPrompts;
    private readonly Action<SecurityEvent> _showPrompt;
    private readonly Action<int> _updateActiveQueuedCount;
    private readonly Action<SecurityEvent> _releaseSuspendedEvent;
    private readonly Queue<SecurityEvent> _queue = new();

    public SecurityEvent? ActiveEvent { get; private set; }
    public int QueuedCount => _queue.Count;

    public ThreatPromptQueueCoordinator(
        int maxQueuedPrompts,
        Action<SecurityEvent> showPrompt,
        Action<int> updateActiveQueuedCount,
        Action<SecurityEvent> releaseSuspendedEvent)
    {
        _maxQueuedPrompts = Math.Max(0, maxQueuedPrompts);
        _showPrompt = showPrompt;
        _updateActiveQueuedCount = updateActiveQueuedCount;
        _releaseSuspendedEvent = releaseSuspendedEvent;
    }

    public void EnqueueOrShow(SecurityEvent incoming)
    {
        // 1. Check exact duplicate prompt in active or queued items
        var duplicate = FindMatchingPrompt(e => IsSamePrompt(e, incoming));
        if (duplicate is not null)
        {
            // Hand over any newly frozen processes/children to the existing prompt
            // without ever resuming processes already owned by the existing prompt!
            MergeSuspendedTargetsInto(duplicate, incoming);
            return;
        }

        // 2. If no active prompt, show immediately
        if (ActiveEvent is null)
        {
            ActiveEvent = incoming;
            _showPrompt(incoming);
            return;
        }

        // 3. Queue saturation handling
        if (_queue.Count >= _maxQueuedPrompts)
        {
            // Prefer handing over frozen targets to an existing prompt for the same root PID if one exists
            if (incoming.ProcessId > 4)
            {
                var sameRootOwner = FindMatchingPrompt(e => e.ProcessId == incoming.ProcessId);
                if (sameRootOwner is not null)
                {
                    MergeSuspendedTargetsInto(sameRootOwner, incoming);
                    return;
                }
            }

            // Otherwise, release ANY suspended root OR child processes so nothing is stranded frozen!
            if (incoming.HasAnySuspendedProcess)
            {
                _releaseSuspendedEvent(incoming);
            }
            return;
        }

        _queue.Enqueue(incoming);
        _updateActiveQueuedCount(_queue.Count);
    }

    public void OnActivePromptClosed(SecurityEvent closedEvent)
    {
        if (ReferenceEquals(ActiveEvent, closedEvent))
        {
            ActiveEvent = null;
        }

        if (ActiveEvent is null && _queue.Count > 0)
        {
            var next = _queue.Dequeue();
            ActiveEvent = next;
            _showPrompt(next);
        }
    }

    public void DrainAllQueued()
    {
        while (_queue.Count > 0)
        {
            var pending = _queue.Dequeue();
            if (pending.HasAnySuspendedProcess)
            {
                try { _releaseSuspendedEvent(pending); } catch { }
            }
        }
    }

    public void ClearActiveWithoutClosing()
    {
        ActiveEvent = null;
    }

    private SecurityEvent? FindMatchingPrompt(Func<SecurityEvent, bool> predicate)
    {
        if (ActiveEvent is not null && predicate(ActiveEvent))
        {
            return ActiveEvent;
        }

        foreach (var queued in _queue)
        {
            if (predicate(queued))
            {
                return queued;
            }
        }

        return null;
    }

    private static bool IsSamePrompt(SecurityEvent a, SecurityEvent b) =>
        a.ProcessId == b.ProcessId &&
        a.Category == b.Category &&
        string.Equals(a.TargetPath, b.TargetPath, StringComparison.OrdinalIgnoreCase);

    private static void MergeSuspendedTargetsInto(SecurityEvent owner, SecurityEvent incoming)
    {
        if (incoming.IsProcessSuspended)
        {
            owner.IsProcessSuspended = true;
            if (owner.ProcessCreationTimeFileTimeUtc == 0 && incoming.ProcessCreationTimeFileTimeUtc != 0)
            {
                owner.ProcessCreationTimeFileTimeUtc = incoming.ProcessCreationTimeFileTimeUtc;
            }
        }

        foreach (var childPid in incoming.SuspendedChildProcessIds)
        {
            if (!owner.SuspendedChildProcessIds.Contains(childPid))
            {
                owner.SuspendedChildProcessIds.Add(childPid);
            }
        }

        foreach (var childInst in incoming.SuspendedChildInstances)
        {
            if (!owner.SuspendedChildInstances.Any(x =>
                    x.ProcessId == childInst.ProcessId &&
                    x.CreationTimeFileTimeUtc == childInst.CreationTimeFileTimeUtc))
            {
                owner.SuspendedChildInstances.Add(childInst);
            }
            if (!owner.SuspendedChildProcessIds.Contains(childInst.ProcessId))
            {
                owner.SuspendedChildProcessIds.Add(childInst.ProcessId);
            }
        }

        owner.AttemptedChildFreezeCount = Math.Max(owner.AttemptedChildFreezeCount, owner.SuspendedChildProcessIds.Count);
        if (incoming.RiskScore > owner.RiskScore)
        {
            owner.RiskScore = incoming.RiskScore;
        }
    }
}
