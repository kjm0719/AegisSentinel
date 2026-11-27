using System.Diagnostics;
using AegisSentinel.Core.Models;
using AegisSentinel.Core.Services;

namespace AegisSentinel.Core.Engine;

/// <summary>
/// User-mode monitor that runs without requiring Administrator elevation.
/// Uses fast process diffing + FileSystemWatcher + Restart Manager attribution.
/// </summary>
public sealed class FallbackProcessAndFileMonitor : IDisposable
{
    private readonly ProcessController _processController;
    private readonly SignatureVerifier _signatureVerifier;
    private readonly ProcessRuleEvaluator _processEvaluator;
    private readonly RansomwareDetector _ransomwareDetector;
    private readonly CanaryManager _canaryManager;
    private readonly Func<GuardPolicy> _policyProvider;
    private readonly Func<IReadOnlyList<(int Pid, string Name)>>? _processSnapshotProvider;
    private readonly TimeSpan _pollInterval;

    private readonly Dictionary<int, long> _knownProcesses = new();
    private readonly List<FileSystemWatcher> _folderWatchers = new();
    private readonly object _sync = new();
    private Timer? _processTimer;
    private int _isPolling;
    private volatile bool _skipProcessScan;

    public bool IsProcessPollingActive
    {
        get
        {
            lock (_sync)
            {
                return !_skipProcessScan && _processTimer is not null;
            }
        }
    }

    public event Action<SecurityEvent>? ThreatDetected;
    public event Action<int, string, string>? NewProcessObserved;

    public FallbackProcessAndFileMonitor(
        ProcessController processController,
        SignatureVerifier signatureVerifier,
        ProcessRuleEvaluator processEvaluator,
        RansomwareDetector ransomwareDetector,
        CanaryManager canaryManager,
        Func<GuardPolicy> policyProvider,
        Func<IReadOnlyList<(int Pid, string Name)>>? processSnapshotProvider = null,
        TimeSpan? pollInterval = null)
    {
        _processController = processController;
        _signatureVerifier = signatureVerifier;
        _processEvaluator = processEvaluator;
        _ransomwareDetector = ransomwareDetector;
        _canaryManager = canaryManager;
        _policyProvider = policyProvider;
        _processSnapshotProvider = processSnapshotProvider;
        _pollInterval = pollInterval ?? TimeSpan.FromMilliseconds(250);
    }

    public void Start(bool processMonitoringHandledByEtw)
    {
        Stop();
        SetProcessPollingEnabled(!processMonitoringHandledByEtw);

        // Always keep FileSystemWatcher active on ProtectedFolders as a safety net for Canary tampering
        // even when ETW is running (in case a file handle was opened prior to ETW session start).
        SetupFolderWatchers();
    }

    /// <summary>
    /// Dynamically enables or disables fallback process polling without tearing down active folder watchers.
    /// Used for live failover when ETW kernel telemetry drops mid-run and clean restoration when ETW recovers.
    /// </summary>
    public void SetProcessPollingEnabled(bool enabled)
    {
        lock (_sync)
        {
            if (enabled)
            {
                if (!_skipProcessScan && _processTimer is not null)
                {
                    return;
                }

                _knownProcesses.Clear();
                foreach (var (pid, _, creationTimeUtc) in CaptureProcessSnapshot())
                {
                    _knownProcesses[pid] = creationTimeUtc;
                }

                _skipProcessScan = false;
                _processTimer?.Dispose();
                _processTimer = new Timer(_ => PollNewProcesses(), null, _pollInterval, _pollInterval);
            }
            else
            {
                _skipProcessScan = true;
                _processTimer?.Dispose();
                _processTimer = null;
                _knownProcesses.Clear();
            }
        }
    }

    public void Stop()
    {
        lock (_sync)
        {
            _skipProcessScan = true;
            _processTimer?.Dispose();
            _processTimer = null;

            foreach (var watcher in _folderWatchers)
            {
                watcher.EnableRaisingEvents = false;
                watcher.Dispose();
            }
            _folderWatchers.Clear();
            _knownProcesses.Clear();
        }
    }

    public void PollNewProcessesOnce() => PollNewProcesses();

    private IReadOnlyList<(int Pid, string Name, long CreationTimeFileTimeUtc)> CaptureProcessSnapshot()
    {
        if (_processSnapshotProvider is not null)
        {
            var raw = _processSnapshotProvider();
            var enriched = new List<(int Pid, string Name, long CreationTimeFileTimeUtc)>(raw.Count);
            foreach (var (pid, name) in raw)
            {
                long creationTimeUtc = _processController.TryGetProcessInstanceIdentity(pid, out var identity) && identity is not null
                    ? identity.CreationTimeFileTimeUtc
                    : 0;
                enriched.Add((pid, name, creationTimeUtc));
            }
            return enriched;
        }

        var result = new List<(int Pid, string Name, long CreationTimeFileTimeUtc)>();
        var currentProcesses = Process.GetProcesses();
        foreach (var proc in currentProcesses)
        {
            try
            {
                long creationTimeUtc = 0;
                if (proc.Id > 4 &&
                    _processController.TryGetProcessInstanceIdentity(proc.Id, out var identity) &&
                    identity is not null &&
                    identity.CreationTimeFileTimeUtc > 0)
                {
                    creationTimeUtc = identity.CreationTimeFileTimeUtc;
                }
                else if (proc.Id > 4)
                {
                    try { creationTimeUtc = proc.StartTime.ToUniversalTime().ToFileTimeUtc(); } catch { }
                }

                result.Add((proc.Id, proc.ProcessName, creationTimeUtc));
            }
            catch
            {
                // Ignore exited processes.
            }
            finally
            {
                proc.Dispose();
            }
        }
        return result;
    }

    private void SetupFolderWatchers()
    {
        var policy = _policyProvider();
        lock (_sync)
        {
            foreach (var folder in policy.ProtectedFolders)
            {
                if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder))
                {
                    continue;
                }

                try
                {
                    var watcher = new FileSystemWatcher(folder)
                    {
                        IncludeSubdirectories = true,
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                        EnableRaisingEvents = true
                    };

                    watcher.Changed += (_, e) => OnFolderEvent(e.FullPath, isRenameOrDelete: false);
                    watcher.Created += (_, e) => OnFolderEvent(e.FullPath, isRenameOrDelete: false);
                    watcher.Renamed += (_, e) => OnFolderEvent(e.FullPath, isRenameOrDelete: true);
                    watcher.Deleted += (_, e) => OnFolderEvent(e.FullPath, isRenameOrDelete: true);

                    _folderWatchers.Add(watcher);
                }
                catch
                {
                    // Ignore unwatched folders.
                }
            }
        }
    }

    private void OnFolderEvent(string fullPath, bool isRenameOrDelete)
    {
        try
        {
            bool isCanary = _canaryManager.IsCanaryPath(fullPath);

            // When Kernel ETW is active (_skipProcessScan == true), ETW already tracks every real FileIOWrite/Delete with exact PID
            // and zero Restart Manager overhead! Only inspect Canary files via FileSystemWatcher as a defense-in-depth backup.
            if (_skipProcessScan && !isCanary)
            {
                return;
            }

            var policy = _policyProvider();
            var pids = ProcessController.GetProcessesLockingFile(fullPath);
            int culpritPid = pids.FirstOrDefault(id => id > 4 && id != Environment.ProcessId && !_processController.IsCriticalProtectedProcess(id));

            if (_skipProcessScan && !isCanary && culpritPid <= 4)
            {
                return;
            }

            string procName = culpritPid > 0 ? _processController.GetProcessNameSafe(culpritPid) : "Unknown (Standard Mode)";
            string procPath = culpritPid > 0 ? _processController.GetExecutablePath(culpritPid) : string.Empty;

            var alert = _ransomwareDetector.RecordFileActivity(
                culpritPid,
                procName,
                procPath,
                fullPath,
                isRenameOrDelete,
                isCanary,
                policy);

            if (alert is not null)
            {
                ThreatDetected?.Invoke(alert);
            }
        }
        catch
        {
            // Keep FileSystemWatcher callback resilient.
        }
    }

    private void PollNewProcesses()
    {
        if (_skipProcessScan || Interlocked.Exchange(ref _isPolling, 1) == 1)
        {
            return;
        }

        try
        {
            var policy = _policyProvider();
            var currentProcesses = CaptureProcessSnapshot();
            var alive = new HashSet<int>();
            var newProcs = new List<(int Id, string Name)>();
            var recycledPids = new List<int>();

            foreach (var (procId, procName, creationTimeUtc) in currentProcesses)
            {
                alive.Add(procId);
                bool isNew = false;
                bool isRecycled = false;
                lock (_sync)
                {
                    if (!_knownProcesses.TryGetValue(procId, out long prevCreationTime))
                    {
                        _knownProcesses[procId] = creationTimeUtc;
                        isNew = true;
                    }
                    else if (prevCreationTime > 0 && creationTimeUtc > 0 && prevCreationTime != creationTimeUtc)
                    {
                        // Same PID reused by a brand-new process instance between consecutive polls!
                        _knownProcesses[procId] = creationTimeUtc;
                        isNew = true;
                        isRecycled = true;
                    }
                    else if (prevCreationTime == 0 && creationTimeUtc > 0)
                    {
                        _knownProcesses[procId] = creationTimeUtc;
                    }
                }

                if (isRecycled)
                {
                    recycledPids.Add(procId);
                }

                if (isNew &&
                    procId > 4 &&
                    procId != Environment.ProcessId &&
                    !InternalHelperProcessRegistry.IsInternalHelper(procId))
                {
                    newProcs.Add((procId, procName));
                }
            }

            List<int> exitedPids;
            lock (_sync)
            {
                exitedPids = _knownProcesses.Keys.Where(id => !alive.Contains(id)).ToList();
                foreach (var id in exitedPids)
                {
                    _knownProcesses.Remove(id);
                }
            }

            foreach (var deadPid in exitedPids.Concat(recycledPids))
            {
                _ransomwareDetector.ClearProcess(deadPid);
            }

            foreach (var (id, name) in newProcs)
            {
                if (_skipProcessScan) break;
                InspectNewProcess(id, name, policy);
            }
        }
        catch
        {
            // Ignore transient enumeration errors.
        }
        finally
        {
            Interlocked.Exchange(ref _isPolling, 0);
        }
    }

    private void InspectNewProcess(int pid, string procName, GuardPolicy policy)
    {
        var procPath = _processController.GetExecutablePath(pid);
        NewProcessObserved?.Invoke(pid, procName, procPath);
        var (parentPid, cmdLine) = _processSnapshotProvider is null
            ? _processController.GetWmiProcessMetadata(pid)
            : (0, string.Empty);
        var parentPath = parentPid > 4 ? _processController.GetExecutablePath(parentPid) : string.Empty;
        var parentName = parentPid > 4
            ? (!string.IsNullOrEmpty(parentPath) ? Path.GetFileNameWithoutExtension(parentPath) : _processController.GetProcessNameSafe(parentPid))
            : string.Empty;

        var sig = !string.IsNullOrWhiteSpace(procPath) && File.Exists(procPath)
            ? _signatureVerifier.VerifyFile(procPath)
            : new SignatureInfo(SignatureStatus.Unknown, string.Empty);

        var ctx = new ProcessEvaluationContext
        {
            ProcessId = pid,
            ProcessName = procName,
            ProcessPath = procPath,
            CommandLine = cmdLine,
            ParentProcessId = parentPid,
            ParentProcessName = parentName,
            ParentProcessPath = parentPath,
            Signature = sig
        };

        var alert = _processEvaluator.Evaluate(ctx, policy);
        if (alert is not null)
        {
            ThreatDetected?.Invoke(alert);
        }
    }

    public void Dispose()
    {
        Stop();
    }
}
