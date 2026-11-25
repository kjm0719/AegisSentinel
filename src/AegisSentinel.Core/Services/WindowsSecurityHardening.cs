using System.Diagnostics;
using System.Text.Json;
using Microsoft.Win32;
using AegisSentinel.Core.Models;

namespace AegisSentinel.Core.Services;

public sealed class WindowsSecurityHardening
{
    private const string AutoStartRegName = "AegisSentinelGuard";
    private const string ElevatedTaskName = "AegisSentinelGuardElevated";

    public static readonly (string Guid, string Name)[] RecommendedAsrRules =
    {
        ("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "LSASS 자격증명 탈취 차단"),
        ("5beb7efe-fd9a-4556-801d-275e5ffc04cc", "난독화된 의심 스크립트 실행 차단"),
        ("d4f940ab-401b-4efc-aadc-ad5f3c50688a", "Office 앱의 비정상 자식 프로세스 생성 차단"),
        ("b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "USB에서 미서명/신뢰되지 않은 실행 파일 차단"),
        ("c1db55ab-c21a-4637-bb3f-a12568109d35", "고급 랜섬웨어 방어 활성화")
    };

    public static async Task<HardeningStatus> GetStatusAsync()
    {
        bool isElevated = ProcessController.IsCurrentProcessElevated();
        bool lsaPpl = CheckLsaProtection();
        bool hvci = CheckMemoryIntegrityHvci();
        bool scriptBlockLogging = CheckPowerShellScriptBlockLogging();
        bool elevatedTask = false;
        try { elevatedTask = await CheckElevatedScheduledTaskExistsAsync(); } catch { }

        try
        {
            var recIds = string.Join(",", RecommendedAsrRules.Select(r => $"'{r.Guid.ToLowerInvariant()}'"));
            var script =
                "$s = Get-MpComputerStatus -ErrorAction Stop; " +
                "$p = Get-MpPreference -ErrorAction Stop; " +
                "$asrIds = @($p.AttackSurfaceReductionRules_Ids); " +
                "$asrActs = @($p.AttackSurfaceReductionRules_Actions); " +
                $"$rec = @({recIds}); " +
                "$activeAsr = 0; " +
                "for ($i=0; $i -lt [Math]::Min($asrIds.Count, $asrActs.Count); $i++) { " +
                "  if ($asrActs[$i] -in 1,2,6 -and ($rec -contains ([string]$asrIds[$i]).ToLowerInvariant())) { $activeAsr++ } " +
                "}; " +
                "@{ RealTime = [bool]$s.RealTimeProtectionEnabled; " +
                "   Tamper = [bool]$s.IsTamperProtected; " +
                "   Cfa = [int]$p.EnableControlledFolderAccess; " +
                "   NetProt = [int]$p.EnableNetworkProtection; " +
                "   Pua = [int]$p.PUAProtection; " +
                "   ActiveAsr = [int]$activeAsr; " +
                "   Folders = @($p.ControlledFolderAccessProtectedFolders) } | ConvertTo-Json -Compress";

            var (code, output, err) = await RunPowerShellAsync(script, elevated: false);
            if (code != 0 || string.IsNullOrWhiteSpace(output))
            {
                return new HardeningStatus(
                    isElevated, false, false, false, false, lsaPpl, false, hvci, scriptBlockLogging,
                    0, elevatedTask, Array.Empty<string>(),
                    string.IsNullOrWhiteSpace(err) ? "Defender 상태를 읽지 못했습니다." : err.Trim());
            }

            using var doc = JsonDocument.Parse(output);
            var root = doc.RootElement;
            bool rt = root.TryGetProperty("RealTime", out var rtEl) && rtEl.ValueKind == JsonValueKind.True;
            bool tamper = root.TryGetProperty("Tamper", out var tEl) && tEl.ValueKind == JsonValueKind.True;
            int cfa = root.TryGetProperty("Cfa", out var cfaEl) && cfaEl.TryGetInt32(out var cVal) ? cVal : 0;
            int net = root.TryGetProperty("NetProt", out var netEl) && netEl.TryGetInt32(out var nVal) ? nVal : 0;
            int pua = root.TryGetProperty("Pua", out var puaEl) && puaEl.TryGetInt32(out var pVal) ? pVal : 0;
            int asr = root.TryGetProperty("ActiveAsr", out var asrEl) && asrEl.TryGetInt32(out var aVal) ? aVal : 0;

            var folders = new List<string>();
            if (root.TryGetProperty("Folders", out var foldersEl))
            {
                if (foldersEl.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in foldersEl.EnumerateArray())
                    {
                        var val = item.GetString();
                        if (!string.IsNullOrWhiteSpace(val)) folders.Add(val);
                    }
                }
                else if (foldersEl.ValueKind == JsonValueKind.String)
                {
                    var val = foldersEl.GetString();
                    if (!string.IsNullOrWhiteSpace(val)) folders.Add(val);
                }
            }

            return new HardeningStatus(
                isElevated, rt, cfa == 1, net == 1, pua == 1, lsaPpl, tamper, hvci, scriptBlockLogging,
                asr, elevatedTask, folders);
        }
        catch (Exception ex)
        {
            return new HardeningStatus(
                isElevated, false, false, false, false, lsaPpl, false, hvci, scriptBlockLogging,
                0, elevatedTask, Array.Empty<string>(), ex.Message);
        }
    }

    public static async Task<(bool Success, string Message)> EnableDefenderKernelHardeningAsync(
        IEnumerable<string> foldersToProtect,
        bool enableScriptBlockLogging = true,
        bool enableAsrRules = true,
        bool asrAuditOnly = false)
    {
        var existingFolders = foldersToProtect
            .Where(f => !string.IsNullOrWhiteSpace(f) && Directory.Exists(f))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(f => $"'{f.Replace("'", "''")}'")
            .ToList();

        var addFoldersCmd = existingFolders.Count > 0
            ? $"Add-MpPreference -ControlledFolderAccessProtectedFolders @({string.Join(",", existingFolders)}) -ErrorAction SilentlyContinue; "
            : string.Empty;

        // Always allow AegisSentinel's own binary in Defender CFA so it never locks itself out
        // when deploying ransomware canaries or restoring user documents from RecoveryVault!
        var selfExe = Environment.ProcessPath;
        var allowSelfCmd = !string.IsNullOrWhiteSpace(selfExe) && File.Exists(selfExe)
            ? $"Add-MpPreference -ControlledFolderAccessAllowedApplications '{selfExe.Replace("'", "''")}' -ErrorAction SilentlyContinue; "
            : string.Empty;

        var sblCmd = enableScriptBlockLogging
            ? "New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Force | Out-Null; " +
              "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord; "
            : string.Empty;

        var asrCmd = string.Empty;
        if (enableAsrRules)
        {
            var ids = string.Join(",", RecommendedAsrRules.Select(r => $"'{r.Guid}'"));
            var action = asrAuditOnly ? "AuditMode" : "Enabled";
            var actions = string.Join(",", RecommendedAsrRules.Select(_ => $"'{action}'"));
            asrCmd = $"Add-MpPreference -AttackSurfaceReductionRules_Ids @({ids}) -AttackSurfaceReductionRules_Actions @({actions}) -ErrorAction SilentlyContinue; ";
        }

        var script =
            "Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction Stop; " +
            "Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue; " +
            "Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue; " +
            addFoldersCmd +
            allowSelfCmd +
            sblCmd +
            asrCmd +
            "Write-Output 'OK'";

        var (code, _, err) = await RunPowerShellAsync(script, elevated: !ProcessController.IsCurrentProcessElevated());
        return code == 0
            ? (true, "Windows Defender 커널 폴더 보호(CFA), 네트워크/PUA 보호, PowerShell 4104 로깅 및 엔터프라이즈 ASR 규칙이 적용되었습니다.")
            : (false, $"설정 적용 실패: {err}");
    }

    public static async Task<(bool Success, string Message)> SetElevatedAutoStartTaskAsync(bool enabled, string exePath)
    {
        if (enabled && string.IsNullOrWhiteSpace(exePath))
        {
            return (false, "실행 파일 경로를 확인할 수 없습니다.");
        }

        var safeExe = (exePath ?? string.Empty).Replace("\"", string.Empty).Replace("'", "''");
        var cmd = enabled
            ? $"$tr = '\"{safeExe}\" --minimized'; schtasks.exe /Create /TN '{ElevatedTaskName}' /TR $tr /SC ONLOGON /RL HIGHEST /F; exit $LASTEXITCODE"
            : $"schtasks.exe /Delete /TN '{ElevatedTaskName}' /F; exit $LASTEXITCODE";

        var (code, _, err) = await RunPowerShellAsync(cmd, elevated: !ProcessController.IsCurrentProcessElevated());
        return code == 0
            ? (true, enabled
                ? "무-UAC 관리자 권한 로그인 자동 실행 작업이 등록되었습니다. 다음 부팅부터 ETW 커널 텔레메트리로 즉시 시작됩니다."
                : "관리자 권한 자동 실행 작업이 해제되었습니다.")
            : (false, $"작업 스케줄러 설정 실패: {err}");
    }

    /// <summary>
    /// Restricts NTFS ACLs on sensitive credential directories (.ssh, .aws, AegisSentinel Vault)
    /// to only the current owner user, SYSTEM, and Administrators, removing broad Users/Everyone access.
    /// </summary>
    public static async Task<(bool Success, string Message)> HardenCredentialFolderAclsAsync(string vaultDirectory)
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var targets = new[]
        {
            Path.Combine(userProfile, ".ssh"),
            Path.Combine(userProfile, ".aws"),
            vaultDirectory
        }.Where(d => !string.IsNullOrWhiteSpace(d) && Directory.Exists(d)).ToList();

        if (targets.Count == 0)
        {
            return (false, "잠금할 대상 폴더(.ssh, .aws, 복구 금고)를 찾지 못했습니다.");
        }

        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var userSid = identity.User?.Value;
        var ownerGrant = !string.IsNullOrWhiteSpace(userSid)
            ? $"*{userSid}:(OI)(CI)F"
            : $"{Environment.UserDomainName}\\{Environment.UserName}".Replace("'", "''") + ":(OI)(CI)F";

        var cmds = new List<string>();
        foreach (var dir in targets)
        {
            var safeDir = dir.Replace("'", "''");
            // Use language-independent well-known SIDs (*S-1-5-18 = SYSTEM, *S-1-5-32-544 = Administrators)
            cmds.Add($"icacls.exe '{safeDir}' /inheritance:r /grant:r '{ownerGrant}' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null; if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}");
        }

        var script = string.Join("; ", cmds) + "; Write-Output 'OK'";
        var (code, _, err) = await RunPowerShellAsync(script, elevated: !ProcessController.IsCurrentProcessElevated());
        return code == 0
            ? (true, $"NTFS 권한 잠금 완료 ({targets.Count}개 폴더: {string.Join(", ", targets.Select(Path.GetFileName))}) — 소유자·SYSTEM·관리자 외 접근 차단됨.")
            : (false, $"NTFS 권한 잠금 실패: {err}");
    }

    public static async Task<bool> CheckElevatedScheduledTaskExistsAsync()
    {
        var (code, _, _) = await RunPowerShellAsync($"schtasks /Query /TN \"{ElevatedTaskName}\" 2>$null", elevated: false);
        return code == 0;
    }

    public static bool IsAutoStartEnabled()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", false);
            return key?.GetValue(AutoStartRegName) is not null;
        }
        catch { return false; }
    }

    public static bool SetAutoStart(bool enabled, string exePath)
    {
        if (enabled && string.IsNullOrWhiteSpace(exePath)) return false;
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", writable: true);
            if (key is null) return false;

            if (enabled)
                key.SetValue(AutoStartRegName, $"\"{exePath}\" --minimized");
            else
                key.DeleteValue(AutoStartRegName, throwOnMissingValue: false);

            return true;
        }
        catch { return false; }
    }

    private static bool CheckLsaProtection()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa", false);
            if (key?.GetValue("RunAsPPL") is int val) return val is 1 or 2;
        }
        catch { }
        return false;
    }

    private static bool CheckMemoryIntegrityHvci()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", false);
            if (key?.GetValue("Enabled") is int val) return val == 1;
        }
        catch { }
        return false;
    }

    private static bool CheckPowerShellScriptBlockLogging()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", false);
            if (key?.GetValue("EnableScriptBlockLogging") is int val) return val == 1;
        }
        catch { }
        return false;
    }

    private static async Task<(int ExitCode, string StdOut, string StdErr)> RunPowerShellAsync(string command, bool elevated)
    {
        var fullCommand = "$ProgressPreference = 'SilentlyContinue'; " + command;
        var encoded = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(fullCommand));

        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}",
            UseShellExecute = elevated,
            CreateNoWindow = !elevated,
            WindowStyle = elevated ? ProcessWindowStyle.Hidden : ProcessWindowStyle.Normal
        };

        if (elevated)
        {
            psi.Verb = "runas";
        }
        else
        {
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
        }

        Process? proc = null;
        if (!elevated) InternalHelperProcessRegistry.BeginSpawnScope();
        try
        {
            proc = Process.Start(psi);
            if (proc is not null)
            {
                InternalHelperProcessRegistry.Register(proc.Id);
            }
        }
        catch (Exception ex)
        {
            return (-1, string.Empty, ex.Message);
        }
        finally
        {
            if (!elevated) InternalHelperProcessRegistry.EndSpawnScope();
        }

        if (proc is null)
        {
            return (-1, string.Empty, "PowerShell을 시작할 수 없습니다.");
        }

        using (proc)
        {
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                if (elevated)
                {
                    await proc.WaitForExitAsync(cts.Token);
                    return (proc.ExitCode, string.Empty, string.Empty);
                }

                var outTask = proc.StandardOutput.ReadToEndAsync(cts.Token);
                var errTask = proc.StandardError.ReadToEndAsync(cts.Token);
                await Task.WhenAll(outTask, errTask, proc.WaitForExitAsync(cts.Token));
                return (proc.ExitCode, outTask.Result, errTask.Result);
            }
            catch (OperationCanceledException)
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                return (-1, string.Empty, "PowerShell 조회 시간 초과 (10초)");
            }
            finally
            {
                InternalHelperProcessRegistry.Unregister(proc.Id);
            }
        }
    }
}
