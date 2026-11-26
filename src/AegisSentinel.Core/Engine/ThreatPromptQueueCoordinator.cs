using AegisSentinel.Core.Models;

namespace AegisSentinel.Core.Engine;

/// <summary>
/// Manages single-active-prompt + FIFO queueing for security intervention dialogs.
/// Guarantees that child-only suspended events are never stranded on queue saturation,
/// duplicate suppression, auto-resume failure, or shutdown, and merging duplicates never
/// prematurely resumes processes still managed by an active/queued prompt.
/// </summary>
public sealed class ThreatPromptQueueCoordinator
{
    private readonly int _maxQueuedPrompts;
    private readonly Action<SecurityEvent> _showPrompt;
    private readonly Action<int> _updateActiveQueuedCount;
    private readonly Func<SecurityEvent, bool> _releaseSuspendedEvent;
    private readonly Queue<SecurityEvent> _queue = new();
    private readonly List<SecurityEvent> _unresolvedRetryEvents = new();

    public SecurityEvent? ActiveEvent { get; private set; }
    public int QueuedCount => _queue.Count;
    public IReadOnlyList<SecurityEvent> UnresolvedRetryEvents => _unresolvedRetryEvents.AsReadOnly();
    public int PendingTotalCount => _queue.Count + _unresolvedRetryEvents.Count;

    public ThreatPromptQueueCoordinator(
        int maxQueuedPrompts,
        Action<SecurityEvent> showPrompt,
        Action<int> updateActiveQueuedCount,
        Func<SecurityEvent, bool> releaseSuspendedEvent)
    {
        _maxQueuedPrompts = Math.Max(0, maxQueuedPrompts);
        _showPrompt = showPrompt;
        _updateActiveQueuedCount = updateActiveQueuedCount;
        _releaseSuspendedEvent = releaseSuspendedEvent;
    }

    public ThreatPromptQueueCoordinator(
        int maxQueuedPrompts,
        Action<SecurityEvent> showPrompt,
        Action<int> updateActiveQueuedCount,
        Action<SecurityEvent> releaseSuspendedEvent)
        : this(
            maxQueuedPrompts,
            showPrompt,
            updateActiveQueuedCount,
            evt =>
            {
                releaseSuspendedEvent(evt);
                return !evt.HasAnySuspendedProcess;
            })
    {
    }

    public void EnqueueOrShow(SecurityEvent incoming)
    {
        // 1. Check exact duplicate prompt in active, queued, or unresolved-retry items
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

            // Otherwise, attempt to release ANY suspended root OR child processes.
            // If release fails (or frozen targets remain), retain in _unresolvedRetryEvents
            // so the user receives a prioritized retry/intervention prompt instead of silently dropping it!
            if (incoming.HasAnySuspendedProcess)
            {
                bool cleared = false;
                try { cleared = _releaseSuspendedEvent(incoming); } catch { cleared = false; }
                if (!cleared || incoming.HasAnySuspendedProcess)
                {
                    var existingUnresolved = incoming.ProcessId > 4
                        ? _unresolvedRetryEvents.FirstOrDefault(e => e.ProcessId == incoming.ProcessId)
                        : null;
                    if (existingUnresolved is not null)
                    {
                        MergeSuspendedTargetsInto(existingUnresolved, incoming);
                    }
                    else
                    {
                        _unresolvedRetryEvents.Add(incoming);
                    }
                    _updateActiveQueuedCount(PendingTotalCount);
                }
            }
            return;
        }

        _queue.Enqueue(incoming);
        _updateActiveQueuedCount(PendingTotalCount);
    }

    /// <summary>
    /// Retries releasing any previously failed saturated-queue suspended events,
    /// returning the number of events that were successfully cleared.
    /// </summary>
    public int RetryUnresolvedReleases()
    {
        int clearedCount = 0;
        for (int i = _unresolvedRetryEvents.Count - 1; i >= 0; i--)
        {
            var evt = _unresolvedRetryEvents[i];
            if (!evt.HasAnySuspendedProcess)
            {
                _unresolvedRetryEvents.RemoveAt(i);
                clearedCount++;
                continue;
            }

            bool cleared = false;
            try { cleared = _releaseSuspendedEvent(evt); } catch { cleared = false; }
            if (cleared && !evt.HasAnySuspendedProcess)
            {
                _unresolvedRetryEvents.RemoveAt(i);
                clearedCount++;
            }
        }

        if (ActiveEvent is not null)
        {
            _updateActiveQueuedCount(PendingTotalCount);
        }

        return clearedCount;
    }

    public void OnActivePromptClosed(SecurityEvent closedEvent)
    {
        if (ReferenceEquals(ActiveEvent, closedEvent))
        {
            ActiveEvent = null;
        }

        if (ActiveEvent is not null)
        {
            return;
        }

        // Prioritize unresolved failed-release frozen events first so the user always gets a retry/kill window!
        while (_unresolvedRetryEvents.Count > 0)
        {
            var unresolved = _unresolvedRetryEvents[0];
            _unresolvedRetryEvents.RemoveAt(0);
            if (!unresolved.HasAnySuspendedProcess)
            {
                continue;
            }
            ActiveEvent = unresolved;
            _showPrompt(unresolved);
            return;
        }

        if (_queue.Count > 0)
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

        while (_unresolvedRetryEvents.Count > 0)
        {
            var unresolved = _unresolvedRetryEvents[0];
            _unresolvedRetryEvents.RemoveAt(0);
            if (unresolved.HasAnySuspendedProcess)
            {
                try { _releaseSuspendedEvent(unresolved); } catch { }
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

        foreach (var unresolved in _unresolvedRetryEvents)
        {
            if (predicate(unresolved))
            {
                return unresolved;
            }
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
