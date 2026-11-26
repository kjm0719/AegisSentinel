using System.ComponentModel;
using System.IO;
using System.Text;
using System.Windows;
using AegisSentinel.Core.Engine;
using AegisSentinel.Core.Models;
using AegisSentinel.Core.Services;

namespace AegisSentinel.App;

public partial class ThreatPromptWindow : Window
{
    private readonly SecurityOrchestrator _orchestrator;
    private readonly SecurityEvent _event;
    private readonly Func<string, string, MessageBoxButton, MessageBoxImage, MessageBoxResult>? _messageBoxOverride;
    private bool _decisionHandled;

    public SecurityEvent SecurityEvent => _event;

    public ThreatPromptWindow(
        SecurityOrchestrator orchestrator,
        SecurityEvent securityEvent,
        int queuedRemainingCount = 0,
        Func<string, string, MessageBoxButton, MessageBoxImage, MessageBoxResult>? messageBoxOverride = null)
    {
        InitializeComponent();
        _orchestrator = orchestrator;
        _event = securityEvent;
        _messageBoxOverride = messageBoxOverride;
        securityEvent.EnsureMitrePopulated();

        // Anchor cleanly at bottom-right of WorkArea without stealing active keyboard focus
        var workArea = SystemParameters.WorkArea;
        Left = Math.Max(workArea.Left + 16, workArea.Right - Width - 20);
        Top = Math.Max(workArea.Top + 16, workArea.Bottom - Height - 20);
        UpdateQueuedCount(queuedRemainingCount);

        SeverityBadgeText.Text = $"{securityEvent.Severity.ToString().ToUpperInvariant()} | {securityEvent.MitreTechniqueId}";
        RiskScoreBadgeText.Text = $"RISK {securityEvent.RiskScore}/100";
        TitleText.Text = securityEvent.Title;
        DescriptionText.Text = securityEvent.Description;
        RefreshSuspensionDisplay();

        bool isInformationalOnly = securityEvent.Category is ThreatCategory.SystemHardening or ThreatCategory.SelfDefenseTamper;
        bool hasExecutablePath = !string.IsNullOrWhiteSpace(securityEvent.ProcessPath) && File.Exists(securityEvent.ProcessPath);
        // Never allow whitelisting, killing, or firewall-blocking core Windows protected OS binaries (svchost/explorer/PhoneExperienceHost/etc.)
        bool isProtectedSystemOrSelf = hasExecutablePath && QuarantineManager.IsProtectedSystemOrSelfPath(securityEvent.ProcessPath);
        bool isCriticalProtectedProcess = securityEvent.ProcessId > 4 &&
                                          _orchestrator.ProcessControl.IsCriticalProtectedProcess(securityEvent.ProcessId);
        bool hasProcess = !isInformationalOnly && securityEvent.ProcessId > 4 && !isCriticalProtectedProcess;
        bool hasQuarantinableArtifact = securityEvent.Category is ThreatCategory.DllHijacking or ThreatCategory.UsbOrDownloadThreat or ThreatCategory.StaticMalware
            && !string.IsNullOrWhiteSpace(securityEvent.TargetPath) && File.Exists(securityEvent.TargetPath);
        bool isRollbackablePersistence = securityEvent.Category == ThreatCategory.Persistence &&
            !string.IsNullOrWhiteSpace(securityEvent.TargetPath) &&
            (securityEvent.TargetPath.StartsWith(@"HKCU\", StringComparison.OrdinalIgnoreCase) ||
             securityEvent.TargetPath.StartsWith(@"HKLM\", StringComparison.OrdinalIgnoreCase) ||
             securityEvent.TargetPath.StartsWith(@"\REGISTRY\", StringComparison.OrdinalIgnoreCase) ||
             File.Exists(securityEvent.TargetPath));
        bool isRollbackableProxy = securityEvent.Category == ThreatCategory.SystemIntegrityTamper &&
                                   !string.IsNullOrWhiteSpace(securityEvent.TargetPath) &&
                                   securityEvent.TargetPath.Contains("Internet Settings", StringComparison.OrdinalIgnoreCase);

        if (isInformationalOnly || !hasExecutablePath || isProtectedSystemOrSelf)
        {
            TrustBtn.Visibility = Visibility.Collapsed;
        }

        if (isInformationalOnly || !hasExecutablePath || isProtectedSystemOrSelf || !hasProcess)
        {
            FirewallBlockBtn.Visibility = Visibility.Collapsed;
        }

        if (isInformationalOnly || (!hasProcess && (!hasExecutablePath || isProtectedSystemOrSelf) && !hasQuarantinableArtifact && !isRollbackablePersistence && !isRollbackableProxy))
        {
            KillQuarantineBtn.Visibility = Visibility.Collapsed;
            AllowOnceBtn.Content = "확인 (닫기)";
        }
        else if (isRollbackableProxy && !hasProcess)
        {
            KillQuarantineBtn.Content = "악성 프록시 즉시 해제";
        }
        else if (isRollbackablePersistence && !hasProcess)
        {
            KillQuarantineBtn.Content = "지속성 항목 즉시 롤백";
        }
        else if (hasQuarantinableArtifact && !hasProcess)
        {
            KillQuarantineBtn.Content = "위험 파일 즉시 격리";
        }
        else if (hasProcess && (!hasExecutablePath || isProtectedSystemOrSelf) && !hasQuarantinableArtifact)
        {
            KillQuarantineBtn.Content = "프로세스 즉시 종료";
        }
    }

    public void RefreshSuspensionDisplay()
    {
        var securityEvent = _event;
        RiskScoreBadgeText.Text = $"RISK {securityEvent.RiskScore}/100";
        if (securityEvent.ActionTaken == SecurityActionTaken.PartiallyAllowed && securityEvent.HasAnySuspendedProcess)
        {
            StatusPillText.Text = $"부분 재개됨 — 아직 동결 중인 대상 재시도 필요 (자식 {securityEvent.SuspendedChildProcessIds.Count}개)";
        }
        else if (securityEvent.IsProcessSuspended)
        {
            StatusPillText.Text = securityEvent.AttemptedChildFreezeCount > 0
                ? $"프로세스 트리 일시정지됨 (부모 + 자식 {securityEvent.SuspendedChildProcessIds.Count}/{securityEvent.AttemptedChildFreezeCount}개 동결)"
                : "프로세스 즉시 일시정지됨 (동결 상태 — 안전 확보)";
        }
        else if (securityEvent.SuspendedChildProcessIds.Count > 0)
        {
            StatusPillText.Text = $"부분 동결 주의 — 부모 실행 중 · 자식 {securityEvent.SuspendedChildProcessIds.Count}/{Math.Max(securityEvent.AttemptedChildFreezeCount, securityEvent.SuspendedChildProcessIds.Count)}개만 동결됨";
        }
        else
        {
            StatusPillText.Text = "실시간 상관분석 보안 경고";
        }

        var sb = new StringBuilder();
        sb.AppendLine($"탐지 시각 : {securityEvent.Timestamp:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"MITRE     : {securityEvent.MitreTechniqueId} ({securityEvent.MitreTactic})");
        sb.AppendLine($"위협 분류 : {securityEvent.Category} | 누적 위험도: {securityEvent.RiskScore}/100");
        if (securityEvent.RiskSignals.Count > 0)
        {
            sb.AppendLine($"탐지 신호 : {string.Join(", ", securityEvent.RiskSignals)}");
        }
        sb.AppendLine($"프로세스  : {securityEvent.ProcessName} (PID: {securityEvent.ProcessId})");
        if (securityEvent.SuspendedChildProcessIds.Count > 0)
        {
            sb.AppendLine($"동결 자식 : PID [{string.Join(", ", securityEvent.SuspendedChildProcessIds)}]");
        }
        if (!string.IsNullOrWhiteSpace(securityEvent.ProcessAncestry))
        {
            sb.AppendLine($"실행 계보 : {securityEvent.ProcessAncestry}");
        }
        if (!string.IsNullOrWhiteSpace(securityEvent.ProcessPath))
        {
            sb.AppendLine($"실행 경로 : {securityEvent.ProcessPath}");
        }
        if (!string.IsNullOrWhiteSpace(securityEvent.RemoteEndpoint))
        {
            sb.AppendLine($"외부 연결 : {securityEvent.RemoteEndpoint} {(string.IsNullOrWhiteSpace(securityEvent.RemoteDomain) ? "" : $"({securityEvent.RemoteDomain})")}");
        }
        if (securityEvent.Signature is not null)
        {
            sb.AppendLine($"디지털서명: {securityEvent.Signature.DisplayLabel}");
        }
        if (!string.IsNullOrWhiteSpace(securityEvent.CommandLine))
        {
            sb.AppendLine($"명령줄    : {securityEvent.CommandLine}");
        }
        if (!string.IsNullOrWhiteSpace(securityEvent.TargetPath))
        {
            sb.AppendLine($"대상 경로 : {securityEvent.TargetPath}");
        }
        if (!string.IsNullOrWhiteSpace(securityEvent.ContainmentDetail))
        {
            sb.AppendLine($"대응 상태 : {securityEvent.ContainmentDetail}");
        }

        ProcessDetailText.Text = sb.ToString();
    }

    public void UpdateQueuedCount(int queuedCount)
    {
        if (queuedCount > 0)
        {
            QueueBadgeText.Text = $"+{queuedCount}건 대기 중";
            QueueBadgeBorder.Visibility = Visibility.Visible;
        }
        else
        {
            QueueBadgeBorder.Visibility = Visibility.Collapsed;
        }
    }

    private void SetActionButtonsEnabled(bool enabled)
    {
        AllowOnceBtn.IsEnabled = enabled;
        TrustBtn.IsEnabled = enabled;
        FirewallBlockBtn.IsEnabled = enabled;
        KillQuarantineBtn.IsEnabled = enabled;
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        // If dismissed via X button or shutdown, safely resume the process WITHOUT granting 30-minute session immunity
        // so real repeat threats can still be caught while never leaving a process silently frozen.
        if (!_decisionHandled)
        {
            _decisionHandled = true;
            _orchestrator.AllowAndResumeProcess(_event, addToWhitelist: false, grantSessionImmunity: false);
        }
        base.OnClosing(e);
    }

    private void OnAllowOnceClick(object sender, RoutedEventArgs e)
    {
        HandleResumeDecision(addToWhitelist: false);
    }

    private void OnTrustAndResumeClick(object sender, RoutedEventArgs e)
    {
        HandleResumeDecision(addToWhitelist: true);
    }

    private MessageBoxResult ShowPromptMessageBox(string message, string caption, MessageBoxButton buttons, MessageBoxImage icon) =>
        _messageBoxOverride is not null
            ? _messageBoxOverride(message, caption, buttons, icon)
            : System.Windows.MessageBox.Show(this, message, caption, buttons, icon);

    private void HandleResumeDecision(bool addToWhitelist)
    {
        var result = _orchestrator.AllowAndResumeProcessDetailed(_event, addToWhitelist, grantSessionImmunity: true);
        if (result.HasAnyPendingRetry)
        {
            RefreshSuspensionDisplay();
            var pending = new List<int>();
            if (result.RootStillSuspended) pending.Add(_event.ProcessId);
            pending.AddRange(result.RemainingSuspendedChildPids);

            ShowPromptMessageBox(
                $"일부 프로세스의 재개가 일시적으로 실패하여 동결 추적 목록에 유지되었습니다.\n\n" +
                $"재시도 필요 PID: {string.Join(", ", pending.Distinct())}\n" +
                $"상태: {_event.ContainmentDetail}\n\n" +
                "다시 허용 버튼을 눌러 재개를 재시도하거나, [종료 및 격리]를 선택할 수 있습니다.",
                "부분 재개 경고 (재시도 필요)",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        _decisionHandled = true;
        Close();
    }

    private async void OnFirewallBlockClick(object sender, RoutedEventArgs e)
    {
        SetActionButtonsEnabled(false);
        try
        {
            var (ok, msg) = await _orchestrator.FirewallBlockProcessAsync(_event);
            System.Windows.MessageBox.Show(this, msg, "Windows 커널 방화벽(WFP)", MessageBoxButton.OK,
                ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
            if (ok)
            {
                _decisionHandled = true;
                Close();
                return;
            }
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show(this, $"방화벽 차단 처리 중 오류: {ex.Message}", "Windows 커널 방화벽(WFP)", MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        // Keep prompt open when firewall block was canceled/failed so the suspended process is never abandoned frozen!
        SetActionButtonsEnabled(true);
    }

    private async void OnKillAndQuarantineClick(object sender, RoutedEventArgs e)
    {
        SetActionButtonsEnabled(false);
        _decisionHandled = true;
        bool ok = false;
        try
        {
            ok = await System.Threading.Tasks.Task.Run(() => _orchestrator.KillAndQuarantine(_event));
        }
        catch { }

        if (!ok)
        {
            System.Windows.MessageBox.Show(
                this,
                "종료 또는 롤백 대상이 이미 종료되었거나 관리자 권한이 필요합니다.",
                "AegisSentinel",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        Close();
    }
}
