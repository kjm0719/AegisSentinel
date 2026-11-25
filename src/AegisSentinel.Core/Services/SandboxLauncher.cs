using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using AegisSentinel.Core.Native;

namespace AegisSentinel.Core.Services;

public sealed class SandboxLaunchResult
{
    public bool Success { get; init; }
    public int ProcessId { get; init; }
    public string SandboxProfileDirectory { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;
}

public sealed class SandboxLauncher
{
    public string SandboxesRoot { get; }

    public SandboxLauncher(string? baseDirectory = null)
    {
        var root = baseDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AegisSentinel");
        SandboxesRoot = Path.Combine(root, "Sandboxes");
        Directory.CreateDirectory(SandboxesRoot);
    }

    public ProcessStartInfo BuildIsolatedStartInfo(string executablePath, string? arguments = null, string? profileName = null)
    {
        if (string.IsNullOrWhiteSpace(executablePath))
        {
            throw new ArgumentException("Executable path cannot be empty.", nameof(executablePath));
        }

        var safeName = SanitizeName(profileName ?? Path.GetFileNameWithoutExtension(executablePath));
        var profileRoot = Path.Combine(SandboxesRoot, safeName);
        var appData = Path.Combine(profileRoot, "AppData", "Roaming");
        var localAppData = Path.Combine(profileRoot, "AppData", "Local");
        var tempDir = Path.Combine(localAppData, "Temp");
        var docsDir = Path.Combine(profileRoot, "Documents");

        Directory.CreateDirectory(appData);
        Directory.CreateDirectory(localAppData);
        Directory.CreateDirectory(tempDir);
        Directory.CreateDirectory(docsDir);

        var psi = new ProcessStartInfo
        {
            FileName = executablePath,
            Arguments = arguments ?? string.Empty,
            WorkingDirectory = Path.GetDirectoryName(executablePath) ?? profileRoot,
            UseShellExecute = false
        };

        // Redirect profile-related environment variables away from real Chrome User Data, .ssh, .aws, etc.
        psi.Environment["USERPROFILE"] = profileRoot;
        psi.Environment["HOME"] = profileRoot;
        if (profileRoot.Length >= 2 && profileRoot[1] == ':')
        {
            psi.Environment["HOMEDRIVE"] = profileRoot[..2];
            psi.Environment["HOMEPATH"] = profileRoot[2..];
        }
        psi.Environment["APPDATA"] = appData;
        psi.Environment["LOCALAPPDATA"] = localAppData;
        psi.Environment["TEMP"] = tempDir;
        psi.Environment["TMP"] = tempDir;

        return psi;
    }

    public SandboxLaunchResult LaunchIsolatedWithJob(string executablePath, string? arguments = null, string? profileName = null)
    {
        if (!File.Exists(executablePath))
        {
            return new SandboxLaunchResult
            {
                Success = false,
                Message = $"파일을 찾을 수 없습니다: {executablePath}"
            };
        }

        try
        {
            var psi = BuildIsolatedStartInfo(executablePath, arguments, profileName);
            var profileRoot = psi.Environment["USERPROFILE"]!;
            using var process = Process.Start(psi);
            if (process is null)
            {
                return new SandboxLaunchResult
                {
                    Success = false,
                    SandboxProfileDirectory = profileRoot,
                    Message = "프로세스를 시작하지 못했습니다."
                };
            }

            // Ensure untrusted sandboxed processes are never treated as internal helpers
            InternalHelperProcessRegistry.Unregister(process.Id);

            // Bind process tree to a Job Object
            var jobHandle = NativeMethods.CreateJobObject(IntPtr.Zero, $"AegisSandbox_{process.Id}");
            if (jobHandle != IntPtr.Zero)
            {
                try
                {
                    var info = new NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
                    info.BasicLimitInformation.LimitFlags = 0; // Track process tree cleanly without killing on handle GC
                    NativeMethods.SetInformationJobObject(
                        jobHandle,
                        NativeMethods.JOBOBJECTINFOCLASS.JobObjectExtendedLimitInformation,
                        ref info,
                        (uint)Marshal.SizeOf<NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION>());
                    NativeMethods.AssignProcessToJobObject(jobHandle, process.Handle);
                }
                finally
                {
                    NativeMethods.CloseHandle(jobHandle);
                }
            }

            return new SandboxLaunchResult
            {
                Success = true,
                ProcessId = process.Id,
                SandboxProfileDirectory = profileRoot,
                Message = $"격리 프로필 환경에서 실행됨 (PID {process.Id})"
            };
        }
        catch (Exception ex)
        {
            return new SandboxLaunchResult
            {
                Success = false,
                Message = $"격리 실행 오류: {ex.Message}"
            };
        }
    }

    public static bool IsWindowsSandboxAvailable()
    {
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsSandbox.exe");
        return File.Exists(path);
    }

    public string GenerateWindowsSandboxConfig(string targetFolderOrExe, bool allowNetworking = true, bool readOnlyFolder = true)
    {
        var hostFolder = File.Exists(targetFolderOrExe)
            ? (Path.GetDirectoryName(targetFolderOrExe) ?? targetFolderOrExe)
            : targetFolderOrExe;
        hostFolder = Path.TrimEndingDirectorySeparator(Path.GetFullPath(hostFolder));

        var escapedHost = SecurityElement.Escape(hostFolder) ?? hostFolder;
        var wsbPath = Path.Combine(SandboxesRoot, $"Aegis_{SanitizeName(Path.GetFileName(hostFolder))}.wsb");
        var netMode = allowNetworking ? "Enable" : "Disable";
        var roFlag = readOnlyFolder ? "true" : "false";

        var xml = $"""
            <Configuration>
              <VGpu>Enable</VGpu>
              <Networking>{netMode}</Networking>
              <ClipboardRedirection>Disable</ClipboardRedirection>
              <MappedFolders>
                <MappedFolder>
                  <HostFolder>{escapedHost}</HostFolder>
                  <SandboxFolder>C:\Users\WDAGUtilityAccount\Desktop\TargetApp</SandboxFolder>
                  <ReadOnly>{roFlag}</ReadOnly>
                </MappedFolder>
              </MappedFolders>
            </Configuration>
            """;

        File.WriteAllText(wsbPath, xml);
        return wsbPath;
    }

    private static string SanitizeName(string raw)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var cleaned = new string(raw.Where(c => !invalid.Contains(c)).ToArray());
        return string.IsNullOrWhiteSpace(cleaned) ? "IsolatedApp" : cleaned;
    }
}
