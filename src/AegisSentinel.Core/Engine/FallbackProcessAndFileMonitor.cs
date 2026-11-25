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

    private readonly HashSet<int> _knownPids = new();
    private readonly List<FileSystemWatcher> _folderWatchers = new();
    private readonly object _sync = new();
    private Timer? _processTimer;
    private int _isPolling;
    private volatile bool _skipProcessScan;

    public event Action<SecurityEvent>? ThreatDetected;

    public FallbackProcessAndFileMonitor(
        ProcessController processController,
        SignatureVerifier signatureVerifier,
        ProcessRuleEvaluator processEvaluator,
        RansomwareDetector ransomwareDetector,
        CanaryManager canaryManager,
        Func<GuardPolicy> policyProvider)
    {
        _processController = processController;
        _signatureVerifier = signatureVerifier;
        _processEvaluator = processEvaluator;
        _ransomwareDetector = ransomwareDetector;
        _canaryManager = canaryManager;
        _policyProvider = policyProvider;
    }

    public void Start(bool processMonitoringHandledByEtw)
    {
        Stop();
        _skipProcessScan = processMonitoringHandledByEtw;

        if (!_skipProcessScan)
        {
            lock (_sync)
            {
                foreach (var p in Process.GetProcesses())
                {
                    _knownPids.Add(p.Id);
                    p.Dispose();
                }
            }

            _processTimer = new Timer(_ => PollNewProcesses(), null, TimeSpan.FromMilliseconds(250), TimeSpan.FromMilliseconds(250));
        }

        // Always keep FileSystemWatcher active on ProtectedFolders as a safety net for Canary tampering
        // even when ETW is running (in case a file handle was opened prior to ETW session start).
        SetupFolderWatchers();
    }

    public void Stop()
    {
        _skipProcessScan = true;
        _processTimer?.Dispose();
        _processTimer = null;

        lock (_sync)
        {
            foreach (var watcher in _folderWatchers)
            {
                watcher.EnableRaisingEvents = false;
                watcher.Dispose();
            }
            _folderWatchers.Clear();
            _knownPids.Clear();
        }
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
            var currentProcesses = Process.GetProcesses();
            var alive = new HashSet<int>();
            var newProcs = new List<(int Id, string Name)>();

            foreach (var proc in currentProcesses)
            {
                try
                {
                    alive.Add(proc.Id);
                    bool isNew;
                    lock (_sync)
                    {
                        isNew = _knownPids.Add(proc.Id);
                    }
                    if (isNew &&
                        proc.Id > 4 &&
                        proc.Id != Environment.ProcessId &&
                        !InternalHelperProcessRegistry.IsInternalHelper(proc.Id))
                    {
                        newProcs.Add((proc.Id, proc.ProcessName));
                    }
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

            List<int> exitedPids;
            lock (_sync)
            {
                exitedPids = _knownPids.Where(id => !alive.Contains(id)).ToList();
                _knownPids.IntersectWith(alive);
            }

            foreach (var deadPid in exitedPids)
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
        var (parentPid, cmdLine) = _processController.GetWmiProcessMetadata(pid);
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
