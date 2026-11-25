using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using AegisSentinel.Core.Models;

namespace AegisSentinel.Core.Services;

/// <summary>
/// Manages Windows Defender Firewall (WFP kernel-level) outbound block rules so compromised
/// executables are immediately cut off from C2 / data exfiltration at the OS network stack.
/// </summary>
public sealed class FirewallController
{
    private const string RulePrefix = "AegisSentinel_Block_";

    public static async Task<(bool Success, string Message)> BlockOutboundExecutableAsync(string executablePath)
    {
        if (string.IsNullOrWhiteSpace(executablePath) || !Path.IsPathFullyQualified(executablePath))
        {
            return (false, "차단할 실행 파일 경로가 유효하지 않습니다.");
        }

        if (QuarantineManager.IsProtectedSystemOrSelfPath(executablePath))
        {
            return (false, "Windows 핵심 시스템 파일 또는 보호된 보안 프로그램은 방화벽 차단 대상에서 제외됩니다.");
        }

        var ruleName = BuildRuleName(executablePath);
        var escapedPath = executablePath.Replace("\"", string.Empty);
        // Remove any prior rule with the same deterministic name to avoid duplicate rule accumulation
        _ = await RunNetshAsync($"advfirewall firewall delete rule name=\"{ruleName}\"", requireElevation: true);
        var args = $"advfirewall firewall add rule name=\"{ruleName}\" dir=out action=block program=\"{escapedPath}\" enable=yes profile=any";

        var (code, _, err) = await RunNetshAsync(args, requireElevation: true);
        return code == 0
            ? (true, $"Windows 커널 방화벽(WFP) 아웃바운드 차단 규칙 추가됨: {Path.GetFileName(executablePath)}")
            : (false, $"방화벽 차단 실패: {err}");
    }

    public static async Task<(bool Success, string Message)> RemoveOutboundBlockAsync(string executablePath)
    {
        return await RemoveRuleByNameAsync(BuildRuleName(executablePath));
    }

    public static async Task<(bool Success, string Message)> RemoveRuleByNameAsync(string ruleName)
    {
        if (string.IsNullOrWhiteSpace(ruleName))
        {
            return (false, "규칙 이름이 비어 있습니다.");
        }

        var safeRule = ruleName.Replace("\"", string.Empty);
        var args = $"advfirewall firewall delete rule name=\"{safeRule}\"";
        var (code, _, err) = await RunNetshAsync(args, requireElevation: true);
        return code == 0
            ? (true, $"방화벽 차단 규칙 제거됨: {safeRule}")
            : (false, $"방화벽 규칙 제거 실패: {err}");
    }

    public static async Task<IReadOnlyList<FirewallRuleInfo>> ListManagedBlockRulesAsync()
    {
        var rules = new List<FirewallRuleInfo>();
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -NonInteractive -Command \"Get-NetFirewallRule -DisplayName 'AegisSentinel_Block_*' -ErrorAction SilentlyContinue | ForEach-Object { $app = ($_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program; Write-Output ($_.DisplayName + '|' + $app + '|' + $_.Direction + '|' + $_.Action) }\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };

            Process? proc = null;
            InternalHelperProcessRegistry.BeginSpawnScope();
            try
            {
                proc = Process.Start(psi);
                if (proc is not null) InternalHelperProcessRegistry.Register(proc.Id);
            }
            finally
            {
                InternalHelperProcessRegistry.EndSpawnScope();
            }

            if (proc is null) return rules;
            int helperPid = proc.Id;
            using (proc)
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(6));
                var output = await proc.StandardOutput.ReadToEndAsync(cts.Token);
                await proc.WaitForExitAsync(cts.Token);

                foreach (var line in output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = line.Split('|');
                    if (parts.Length >= 4)
                    {
                        rules.Add(new FirewallRuleInfo(parts[0].Trim(), parts[1].Trim(), parts[2].Trim(), parts[3].Trim()));
                    }
                }
            }
            catch (OperationCanceledException)
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
            }
            finally
            {
                InternalHelperProcessRegistry.Unregister(helperPid);
            }
        }
        catch
        {
            // Ignore when NetSecurity cmdlets are unavailable.
        }

        return rules;
    }

    public static string BuildRuleName(string executablePath)
    {
        var raw = executablePath ?? string.Empty;
        var name = Path.GetFileNameWithoutExtension(raw).ToLowerInvariant();
        var normalized = raw.Trim().Replace('/', '\\').ToLowerInvariant();
        var shaBytes = SHA256.HashData(Encoding.UTF8.GetBytes(normalized));
        var deterministicHash = Convert.ToHexString(shaBytes)[..8];
        var safeName = new string(name.Where(char.IsLetterOrDigit).ToArray());
        return $"{RulePrefix}{(string.IsNullOrEmpty(safeName) ? "App" : safeName)}_{deterministicHash}";
    }

    private static async Task<(int ExitCode, string StdOut, string Error)> RunNetshAsync(string arguments, bool requireElevation)
    {
        bool needElevation = requireElevation && !ProcessController.IsCurrentProcessElevated();
        var psi = new ProcessStartInfo
        {
            FileName = "netsh.exe",
            Arguments = arguments,
            UseShellExecute = needElevation,
            CreateNoWindow = !needElevation,
            WindowStyle = needElevation ? ProcessWindowStyle.Hidden : ProcessWindowStyle.Normal
        };

        if (needElevation)
        {
            psi.Verb = "runas";
        }
        else
        {
            psi.RedirectStandardError = true;
            psi.RedirectStandardOutput = true;
        }

        try
        {
            Process? proc = null;
            if (!needElevation) InternalHelperProcessRegistry.BeginSpawnScope();
            try
            {
                proc = Process.Start(psi);
                if (proc is not null) InternalHelperProcessRegistry.Register(proc.Id);
            }
            finally
            {
                if (!needElevation) InternalHelperProcessRegistry.EndSpawnScope();
            }

            if (proc is null)
            {
                return (-1, string.Empty, "netsh 실행 실패");
            }

            int helperPid = proc.Id;
            using (proc)
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(8));
                if (needElevation)
                {
                    await proc.WaitForExitAsync(cts.Token);
                    return (proc.ExitCode, string.Empty, string.Empty);
                }

                var outTask = proc.StandardOutput.ReadToEndAsync(cts.Token);
                var errTask = proc.StandardError.ReadToEndAsync(cts.Token);
                await Task.WhenAll(outTask, errTask, proc.WaitForExitAsync(cts.Token));
                return (proc.ExitCode, outTask.Result.Trim(), errTask.Result.Trim());
            }
            catch (OperationCanceledException)
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                return (-1, string.Empty, "netsh 실행 시간 초과 (8초)");
            }
            finally
            {
                InternalHelperProcessRegistry.Unregister(helperPid);
            }
        }
        catch (Exception ex)
        {
            return (-1, string.Empty, ex.Message);
        }
    }
}
