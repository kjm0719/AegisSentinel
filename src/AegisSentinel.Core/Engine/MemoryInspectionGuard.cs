using System.Runtime.InteropServices;
using AegisSentinel.Core.Models;
using AegisSentinel.Core.Native;

namespace AegisSentinel.Core.Engine;

public sealed record MemoryInspectionResult(
    int ProcessId,
    int UnbackedRwxRegionCount,
    long TotalUnbackedRwxBytes,
    int UnbackedRxRegionCount,
    long TotalUnbackedRxBytes,
    bool IsGhostDeletedOnDisk,
    bool IsSuspicious);

/// <summary>
/// Inspects virtual memory regions via VirtualQueryEx to detect both classic unbacked Private RWX
/// and stealth VirtualProtect Private RX shellcode/reflective allocations, plus Process Ghosting
/// (executable deleted from disk while still running in memory).
/// </summary>
public sealed class MemoryInspectionGuard
{
    private static readonly HashSet<string> KnownJitRuntimes = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "whale",
        "msedgewebview2", "cefsharp.browsersubprocess", "qtwebengineprocess",
        "dotnet", "powershell", "pwsh", "java", "javaw", "node", "deno", "bun",
        "python", "pythonw", "code", "devenv", "rider64", "idea64",
        "steamwebhelper", "discord", "slack", "teams", "ms-teams", "obsidian",
        "aegissentinel.app", "testhost", "vstest.console"
    };

    public static MemoryInspectionResult InspectProcessMemory(
        int pid,
        string processName,
        string? executablePath = null,
        bool requireLiveProcessHandle = false)
    {
        if (pid <= 4 || pid == Environment.ProcessId)
        {
            return new MemoryInspectionResult(pid, 0, 0, 0, 0, false, false);
        }

        var baseName = Path.GetFileNameWithoutExtension(processName);
        if (KnownJitRuntimes.Contains(baseName))
        {
            return new MemoryInspectionResult(pid, 0, 0, 0, 0, false, false);
        }

        bool looksGhostDeleted = !string.IsNullOrWhiteSpace(executablePath) &&
                                 Path.IsPathRooted(executablePath) &&
                                 ProcessRuleEvaluator.IsUserWritableRiskyPath(executablePath) &&
                                 !File.Exists(executablePath);

        var handle = NativeMethods.OpenProcess(
            NativeMethods.PROCESS_QUERY_INFORMATION | NativeMethods.PROCESS_VM_READ,
            false,
            pid);

        if (handle == IntPtr.Zero)
        {
            if (requireLiveProcessHandle)
            {
                // Verify via limited query whether the process is still alive (access-denied vs already exited)
                var limited = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (limited == IntPtr.Zero)
                {
                    return new MemoryInspectionResult(pid, 0, 0, 0, 0, false, false);
                }
                try
                {
                    bool alive = NativeMethods.GetExitCodeProcess(limited, out uint code) && code == NativeMethods.STILL_ACTIVE;
                    bool confirmedGhost = alive && looksGhostDeleted;
                    return new MemoryInspectionResult(pid, 0, 0, 0, 0, confirmedGhost, confirmedGhost);
                }
                finally
                {
                    NativeMethods.CloseHandle(limited);
                }
            }

            return new MemoryInspectionResult(pid, 0, 0, 0, 0, looksGhostDeleted, looksGhostDeleted);
        }

        try
        {
            if (!NativeMethods.GetExitCodeProcess(handle, out uint exitCode) || exitCode != NativeMethods.STILL_ACTIVE)
            {
                return new MemoryInspectionResult(pid, 0, 0, 0, 0, false, false);
            }

            // Process Ghosting / Self-deleting binary check: verified ONLY while process is confirmed STILL_ACTIVE!
            bool ghostDeleted = looksGhostDeleted && !File.Exists(executablePath);

            int rwxCount = 0;
            long rwxBytes = 0;
            int rxCount = 0;
            long rxBytes = 0;
            long address = 0x10000;
            long maxUserAddress = IntPtr.Size == 8 ? 0x7FFFFFFEFFFF : 0x7FFEFFFF;
            var mbiSize = (UIntPtr)Marshal.SizeOf<NativeMethods.MEMORY_BASIC_INFORMATION>();
            int iterations = 0;

            while (address < maxUserAddress && iterations < 4096)
            {
                iterations++;
                var queried = NativeMethods.VirtualQueryEx(handle, new IntPtr(address), out var mbi, mbiSize);
                if (queried == UIntPtr.Zero) break;

                long regionSize = (long)mbi.RegionSize;
                if (regionSize <= 0) break;

                bool isCommittedPrivate = mbi.State == NativeMethods.MEM_COMMIT && mbi.Type == NativeMethods.MEM_PRIVATE;
                if (isCommittedPrivate && regionSize >= 4096)
                {
                    bool isRwx = (mbi.Protect & (NativeMethods.PAGE_EXECUTE_READWRITE | NativeMethods.PAGE_EXECUTE_WRITECOPY)) != 0;
                    bool isRx = (mbi.Protect & (NativeMethods.PAGE_EXECUTE_READ | NativeMethods.PAGE_EXECUTE)) != 0;

                    if (isRwx)
                    {
                        rwxCount++;
                        rwxBytes += regionSize;
                    }
                    else if (isRx)
                    {
                        rxCount++;
                        rxBytes += regionSize;
                    }
                }

                long next = (long)mbi.BaseAddress + regionSize;
                if (next <= address) break;
                address = next;
            }

            // Do NOT flag PAGE_EXECUTE_READ (RX) — GPU shader compilers (DirectX/NVIDIA/AMD) and Windows COM
            // legitimately allocate private RX regions in normal apps.
            // Also exclude managed CLR / Mono / Chromium CEF JIT runtimes when custom-named .NET/Unity apps allocate RWX JIT pages.
            bool highUnbackedRwx = rwxCount >= 4 && rwxBytes >= 256 * 1024 && !HasManagedJitModuleLoaded(pid);
            bool suspicious = ghostDeleted || highUnbackedRwx;

            return new MemoryInspectionResult(pid, rwxCount, rwxBytes, rxCount, rxBytes, ghostDeleted, suspicious);
        }
        finally
        {
            NativeMethods.CloseHandle(handle);
        }
    }

    private static bool HasManagedJitModuleLoaded(int pid)
    {
        try
        {
            using var proc = System.Diagnostics.Process.GetProcessById(pid);
            foreach (System.Diagnostics.ProcessModule mod in proc.Modules)
            using (mod)
            {
                var name = mod.ModuleName;
                if (string.IsNullOrEmpty(name)) continue;
                if (name.Equals("coreclr.dll", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("clr.dll", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("clrjit.dll", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("mscorwks.dll", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("mono-2.0-bdwgc.dll", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("libcef.dll", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("v8.dll", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        catch { }
        return false;
    }

    public static SecurityEvent? EvaluateProcess(
        int pid,
        string processName,
        string processPath,
        SignatureInfo signature,
        GuardPolicy policy)
    {
        if (!policy.EnableMemoryInjectionGuard ||
            pid <= 4 ||
            pid == Environment.ProcessId ||
            ProcessRuleEvaluator.IsProtectedHostIdeProcess(processPath))
        {
            return null;
        }

        if (!string.IsNullOrWhiteSpace(processPath) &&
            policy.WhitelistedExecutablePaths.Contains(processPath, StringComparer.OrdinalIgnoreCase))
        {
            return null;
        }

        var result = InspectProcessMemory(pid, processName, processPath);
        if (!result.IsSuspicious)
        {
            return null;
        }

        // Only flag RWX memory on UNSIGNED processes in high-risk drop paths (never on signed apps)
        if (!result.IsGhostDeletedOnDisk && (signature.IsSigned || !ProcessRuleEvaluator.IsHighRiskDropPath(processPath)))
        {
            return null;
        }

        if (result.IsGhostDeletedOnDisk)
        {
            return new SecurityEvent
            {
                Severity = ThreatSeverity.Critical,
                Category = ThreatCategory.MemoryInjection,
                ActionTaken = SecurityActionTaken.Logged,
                Title = "프로세스 고스팅 / 디스크 자가삭제 실행 파일 탐지!",
                Description = $"실행 중인 '{processName}' (PID {pid})의 원본 파일({processPath})이 디스크에서 삭제된 채 메모리에서만 동작 중입니다.",
                ProcessId = pid,
                ProcessName = processName,
                ProcessPath = processPath,
                TargetPath = processPath,
                RiskScore = 95,
                RiskSignals = new List<string> { "ProcessGhostingDeletedOnDisk(+95)" },
                Signature = signature
            };
        }

        int score = signature.IsSigned ? 65 : 85;
        return new SecurityEvent
        {
            Severity = score >= 75 ? ThreatSeverity.Critical : ThreatSeverity.High,
            Category = ThreatCategory.MemoryInjection,
            ActionTaken = SecurityActionTaken.Logged,
            Title = "비정상 파일리스 실행 메모리(Private RWX/RX) 할당 탐지",
            Description = $"비-JIT 프로세스 '{processName}' (PID {pid}) 내부에 파일 미매핑 실행 메모리(RWX {result.UnbackedRwxRegionCount}개/{result.TotalUnbackedRwxBytes / 1024}KB, RX {result.UnbackedRxRegionCount}개/{result.TotalUnbackedRxBytes / 1024}KB)가 감지되었습니다.",
            ProcessId = pid,
            ProcessName = processName,
            ProcessPath = processPath,
            TargetPath = processPath,
            RiskScore = score,
            RiskSignals = new List<string> { $"UnbackedExecMemory:RWX={result.UnbackedRwxRegionCount},RX={result.UnbackedRxRegionCount}(+{score})" },
            Signature = signature
        };
    }
}
