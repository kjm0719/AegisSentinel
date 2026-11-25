using System.Diagnostics;
using AegisSentinel.Core.Models;
using AegisSentinel.Core.Services;

namespace AegisSentinel.Core.Engine;

public sealed record DllSideloadFinding(
    bool IsSideloading,
    string ThreatName,
    int RiskScore,
    ThreatSeverity Severity,
    string Reason,
    string? HostExePath = null);

/// <summary>
/// Supply-Chain DLL Search-Order Hijacking &amp; Sideloading Detector (Anti-NIKKE / APT / Game-Launcher Hijack Engine).
/// Commercial AVs often trust legitimately signed host executables (game launchers, updaters, OneDrive, Teams)
/// while missing an unsigned malicious proxy DLL (e.g. version.dll, winmm.dll, dbghelp.dll, winhttp.dll) dropped next to it.
/// Detects BOTH:
/// 1) Static DLL sideloading on disk (unsigned System32 proxy DLL planted next to a signed .exe or in high-risk user folder)
/// 2) Live in-memory DLL sideloading (signed running process that loaded an unsigned System32-colliding DLL from outside Windows\)
/// </summary>
public static class DllSideloadingDetector
{
    private static readonly string System32Dir =
        Environment.GetFolderPath(Environment.SpecialFolder.System);

    private static readonly string WindowsDir =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\', '/') + "\\";

    /// <summary>
    /// High-abuse Windows System32 DLLs routinely weaponized in DLL sideloading supply-chain attacks
    /// (NIKKE/game launcher trojans, PlugX, ShadowPad, Cobalt Strike, QakBot, Lumma).
    /// </summary>
    public static readonly HashSet<string> HighAbuseSystemProxyDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "version.dll", "winmm.dll", "winhttp.dll", "wininet.dll",
        "dbghelp.dll", "dbgcore.dll", "dwmapi.dll", "uxtheme.dll",
        "cryptbase.dll", "cryptsp.dll", "msimg32.dll", "wtsapi32.dll",
        "secur32.dll", "sspicli.dll", "userenv.dll", "profapi.dll",
        "propsys.dll", "netapi32.dll", "iphlpapi.dll", "dnsapi.dll",
        "mpr.dll", "netutils.dll", "samcli.dll", "srvcli.dll", "wkscli.dll",
        "winsta.dll", "hid.dll", "textshaping.dll", "edputil.dll",
        "linkinfo.dll", "ntmarta.dll", "cscapi.dll", "duser.dll",
        "shfolder.dll", "cabinet.dll", "urlmon.dll", "msasn1.dll"
    };

    /// <summary>
    /// Static disk check: flags an unsigned DLL masquerading as a Windows System32 DLL when located
    /// outside Windows\System32 and either co-located with a signed .exe (classic sideloading pair)
    /// or dropped inside a high-risk user folder.
    /// </summary>
    public static DllSideloadFinding InspectDiskDll(
        string dllPath,
        SignatureInfo dllSignature,
        SignatureVerifier verifier)
    {
        if (string.IsNullOrWhiteSpace(dllPath) ||
            !dllPath.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
        {
            return Clean();
        }

        // Validly signed DLLs (Microsoft or trusted vendor) are not unsigned sideloading proxies
        if (dllSignature.IsSigned) return Clean();

        var fileName = Path.GetFileName(dllPath);
        if (!HighAbuseSystemProxyDlls.Contains(fileName)) return Clean();

        string fullPath;
        try { fullPath = Path.GetFullPath(dllPath); }
        catch { return Clean(); }

        // Never flag official Windows OS directories
        if (!string.IsNullOrEmpty(WindowsDir) &&
            fullPath.StartsWith(WindowsDir, StringComparison.OrdinalIgnoreCase))
        {
            return Clean();
        }

        // Confirm the candidate DLL actually has a valid MZ/PE binary header (avoid flagging 0-byte or text placeholders)
        if (!PeStaticAnalyzer.AnalyzeFile(fullPath).IsValidPe)
        {
            return Clean();
        }

        var parentDir = Path.GetDirectoryName(fullPath);
        if (string.IsNullOrWhiteSpace(parentDir) || !Directory.Exists(parentDir))
        {
            return Clean();
        }

        // 1. Check if this unsigned System32 proxy DLL sits right next to a VALIDLY SIGNED .exe (classic sideloading pair!)
        string? signedSiblingExe = null;
        try
        {
            foreach (var exePath in Directory.EnumerateFiles(parentDir, "*.exe").Take(12))
            {
                var exeSig = verifier.VerifyFile(exePath);
                if (exeSig.IsSigned)
                {
                    signedSiblingExe = exePath;
                    break;
                }
            }
        }
        catch { }

        if (!string.IsNullOrWhiteSpace(signedSiblingExe))
        {
            return new DllSideloadFinding(
                true,
                "SupplyChain.DllSideloading.ProxyHijack",
                94,
                ThreatSeverity.Critical,
                $"공급망 DLL 사이드로딩(검색 순서 하이재킹) 탐지! 서명된 정상 실행파일('{Path.GetFileName(signedSiblingExe)}') 옆에 미서명 Windows 시스템명 위장 DLL('{fileName}')이 배치되어 있습니다.",
                signedSiblingExe);
        }

        // 2. Even without a sibling .exe yet, an unsigned System32 proxy DLL in Downloads/Desktop/Temp/Public/Startup is critical!
        if (ProcessRuleEvaluator.IsHighRiskDropPath(fullPath))
        {
            return new DllSideloadFinding(
                true,
                "SupplyChain.DllSideloading.StagedProxyDll",
                85,
                ThreatSeverity.Critical,
                $"고위험 사용자 경로에 Windows 시스템 DLL 명칭('{fileName}')을 사칭한 미서명 프록시 DLL이 배치되어 있습니다 (사이드로딩 스테이징 의심).");
        }

        return Clean();
    }

    /// <summary>
    /// Live memory check: inspects loaded modules of a running signed process to detect an active
    /// DLL sideloading attack where a signed host loaded an unsigned System32-colliding DLL from outside Windows\.
    /// </summary>
    public static List<MalwareThreatItem> InspectRunningProcessModules(
        Process proc,
        string hostExePath,
        SignatureInfo hostSignature,
        SignatureVerifier verifier,
        CancellationToken ct = default)
    {
        var results = new List<MalwareThreatItem>();
        if (!hostSignature.IsSigned || string.IsNullOrWhiteSpace(System32Dir)) return results;

        try
        {
            foreach (ProcessModule module in proc.Modules)
            using (module)
            {
                ct.ThrowIfCancellationRequested();
                var modPath = module.FileName;
                if (string.IsNullOrWhiteSpace(modPath) ||
                    !modPath.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                // Only inspect DLLs loaded from outside C:\Windows\
                if (!string.IsNullOrEmpty(WindowsDir) &&
                    modPath.StartsWith(WindowsDir, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var dllName = Path.GetFileName(modPath);
                if (!HighAbuseSystemProxyDlls.Contains(dllName)) continue;

                // Confirm a real Windows System32 DLL with the exact same name exists
                if (!File.Exists(Path.Combine(System32Dir, dllName))) continue;

                var modSig = verifier.VerifyFile(modPath);
                if (modSig.IsSigned) continue;

                bool canQuarantine = File.Exists(modPath) && !QuarantineManager.IsProtectedSystemOrSelfPath(modPath);
                bool isKnownGameModFolder =
                    (modPath.Contains(@"\steamapps\common\", StringComparison.OrdinalIgnoreCase) ||
                     modPath.Contains(@"\GOG Galaxy\Games\", StringComparison.OrdinalIgnoreCase)) &&
                    !ThreatScanner.HasMarkOfTheWeb(modPath);
                results.Add(new MalwareThreatItem
                {
                    Stage = MalwareScanStage.ActiveProcessAndMemory,
                    ThreatName = "SupplyChain.LiveDllSideloading.ActiveHijack",
                    CategoryLabel = "실시간 DLL 사이드로딩 공격",
                    Severity = isKnownGameModFolder ? ThreatSeverity.High : ThreatSeverity.Critical,
                    RiskScore = isKnownGameModFolder ? 78 : 98,
                    TargetPath = modPath,
                    EntryName = $"{proc.ProcessName} (PID {proc.Id}) ← {dllName}",
                    ProcessId = proc.Id,
                    SignatureLabel = modSig.DisplayLabel,
                    Description = $"서명된 프로세스 '{Path.GetFileName(hostExePath)}'가 Windows\\System32 대신 외부 경로의 미서명 시스템명 DLL('{modPath}')을 로드했습니다!{(isKnownGameModFolder ? " (게임 모드 로더일 경우 수동 확인)" : " (니케/공급망형 사이드로딩 기법)")}",
                    ActionType = canQuarantine ? RemediationActionType.TerminateAndQuarantine : RemediationActionType.ManualReview,
                    RecommendedForCure = canQuarantine && !isKnownGameModFolder
                });
            }
        }
        catch { }

        return results;
    }

    private static DllSideloadFinding Clean() =>
        new(false, string.Empty, 0, ThreatSeverity.Info, string.Empty);
}
