using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using AegisSentinel.Core.Engine;
using AegisSentinel.Core.Models;
using AegisSentinel.Core.Services;
using Win32 = Microsoft.Win32;
using WinForms = System.Windows.Forms;
using MediaColor = System.Windows.Media.Color;

namespace AegisSentinel.App;

public sealed class SecurityEventRow
{
    public SecurityEvent Source { get; }
    public string TimeText => Source.Timestamp.ToString("HH:mm:ss");
    public string RiskText => $"{Source.RiskScore}/100";
    public string SeverityText => Source.Severity.ToString().ToUpperInvariant();
    public string MitreText => string.IsNullOrWhiteSpace(Source.MitreTechniqueId) ? "-" : Source.MitreTechniqueId;
    public string CategoryText => Source.Category.ToString();
    public string ActionText => Source.ActionTaken.ToString();
    public string ProcessText => Source.ProcessId > 0 ? $"{Source.ProcessName} ({Source.ProcessId})" : Source.ProcessName;
    public string SummaryText
    {
        get
        {
            var extra = !string.IsNullOrWhiteSpace(Source.RemoteEndpoint)
                ? $" [{Source.RemoteEndpoint}{(string.IsNullOrWhiteSpace(Source.RemoteDomain) ? "" : $" / {Source.RemoteDomain}")}]"
                : (!string.IsNullOrWhiteSpace(Source.TargetPath) ? $" — {Source.TargetPath}" : string.Empty);
            return $"{Source.Title}{extra}";
        }
    }
    public string SignatureText => Source.Signature?.DisplayLabel ?? "-";

    public SecurityEventRow(SecurityEvent source) => Source = source;
}

public sealed class ScanFindingRow : INotifyPropertyChanged
{
    private bool _isSelected;
    private string _statusText = "탐지됨";

    public MalwareThreatItem Source { get; }
    public string RiskText => $"{Source.RiskScore}/100";
    public string SeverityText => Source.Severity.ToString().ToUpperInvariant();
    public string ThreatName => Source.ThreatName;
    public string CategoryLabel => Source.CategoryLabel;
    public string TargetPath => Source.TargetPath;
    public string FilePath => Source.TargetPath;
    public string SignatureText => Source.SignatureLabel;
    public string Description => Source.Description;

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (_isSelected == value) return;
            _isSelected = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsSelected)));
        }
    }

    public string StatusText
    {
        get => _statusText;
        set
        {
            if (_statusText == value) return;
            _statusText = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(StatusText)));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CanCure)));
        }
    }

    public bool CanCure =>
        Source.ActionType != RemediationActionType.ManualReview &&
        Source.RiskScore >= 40 &&
        !string.Equals(_statusText, "치료 완료", StringComparison.Ordinal);

    public event PropertyChangedEventHandler? PropertyChanged;

    public ScanFindingRow(MalwareThreatItem source)
    {
        Source = source;
        _statusText = source.RiskScore < 40 ? "정상" : "탐지됨";
        _isSelected = source.RecommendedForCure && CanCure;
    }
}

public sealed class ConnectionRow
{
    public ActiveNetworkConnection Source { get; }
    public int ProcessId => Source.ProcessId;
    public string ProcessName => Source.ProcessName;
    public string ProcessPath => Source.ProcessPath;
    public string EndpointText => $"{Source.RemoteIp}:{Source.RemotePort}";
    public string RemoteDomain => string.IsNullOrWhiteSpace(Source.RemoteDomain) ? "-" : Source.RemoteDomain;
    public int RiskScore => Source.RiskScore;
    public string SignatureLabel => Source.SignatureLabel;

    public ConnectionRow(ActiveNetworkConnection source) => Source = source;
}

public sealed class PersistenceRow
{
    public PersistenceEntry Source { get; }
    public string Category => Source.Category;
    public string Name => Source.Name;
    public string Value => Source.Value;
    public string SourceLocation => Source.SourceLocation;
    public string SignatureText => Source.Signature?.DisplayLabel ?? "-";

    public PersistenceRow(PersistenceEntry source) => Source = source;
}

public sealed class QuarantineRow
{
    public QuarantineEntry Source { get; }
    public string TimeText => Source.QuarantinedAt.ToString("yyyy-MM-dd HH:mm");
    public string OriginalPath => Source.OriginalPath;
    public string Reason => Source.Reason;

    public QuarantineRow(QuarantineEntry source) => Source = source;
}

public sealed class VaultSnapshotRow
{
    public VaultSnapshotEntry Source { get; }
    public string TimeText => Source.CapturedAt.ToString("yyyy-MM-dd HH:mm");
    public string OriginalPath => Source.OriginalPath;
    public string SizeText => Source.FileSize < 1024 ? $"{Source.FileSize} B" : $"{Source.FileSize / 1024.0:F1} KB";

    public VaultSnapshotRow(VaultSnapshotEntry source) => Source = source;
}

public partial class MainWindow : Window
{
    private readonly SecurityOrchestrator _orchestrator;
    private readonly SandboxLauncher _sandboxLauncher = new();

    private readonly List<SecurityEventRow> _allEventRows = new();
    private readonly ObservableCollection<SecurityEventRow> _filteredEventRows = new();
    private readonly ObservableCollection<SecurityEventRow> _recentDashboardRows = new();
    private readonly ObservableCollection<ScanFindingRow> _scanFindingRows = new();
    private readonly ObservableCollection<ConnectionRow> _connectionRows = new();
    private readonly ObservableCollection<FirewallRuleInfo> _firewallRuleRows = new();
    private readonly ObservableCollection<PersistenceRow> _persistenceRows = new();
    private readonly ObservableCollection<QuarantineRow> _quarantineRows = new();
    private readonly ObservableCollection<VaultSnapshotRow> _vaultRows = new();

    private const int WM_CLIPBOARDUPDATE = 0x031D;
    private const int WM_DEVICECHANGE = 0x0219;
    private const int DBT_DEVICEARRIVAL = 0x8000;

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AddClipboardFormatListener(IntPtr hwnd);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RemoveClipboardFormatListener(IntPtr hwnd);

    private static readonly SolidColorBrush BrushBadgeActiveBg = CreateFrozenBrush(6, 78, 59);
    private static readonly SolidColorBrush BrushBadgePausedBg = CreateFrozenBrush(127, 29, 29);
    private static readonly SolidColorBrush BrushBadgeActiveFg = CreateFrozenBrush(110, 231, 183);
    private static readonly SolidColorBrush BrushBadgePausedFg = CreateFrozenBrush(252, 165, 165);
    private static readonly SolidColorBrush BrushCardActiveFg = CreateFrozenBrush(16, 185, 129);
    private static readonly SolidColorBrush BrushCardInactiveFg = CreateFrozenBrush(148, 163, 184);

    private static SolidColorBrush CreateFrozenBrush(byte r, byte g, byte b)
    {
        var brush = new SolidColorBrush(MediaColor.FromRgb(r, g, b));
        brush.Freeze();
        return brush;
    }

    private HardeningStatus? _lastHardeningStatus;
    private bool _suppressUiEvents;
    private bool _isScanning;
    private CancellationTokenSource? _scanCts;
    private HwndSource? _hwndSource;
    private IntPtr _registeredHwnd;
    private string _lastClipboardSample = string.Empty;
    private Action<SecurityEvent>? _onEventRecordedHandler;
    private Action<string>? _onEngineStatusHandler;
    private Action<string>? _onDatabaseUpdatedHandler;

    public bool AllowClose { get; set; }

    public MainWindow(SecurityOrchestrator orchestrator)
    {
        _orchestrator = orchestrator;
        _suppressUiEvents = true;
        try
        {
            InitializeComponent();
        }
        finally
        {
            _suppressUiEvents = false;
        }

        EventsListView.ItemsSource = _filteredEventRows;
        DashboardRecentListView.ItemsSource = _recentDashboardRows;
        ScanFindingsListView.ItemsSource = _scanFindingRows;
        ConnectionsListView.ItemsSource = _connectionRows;
        FirewallRulesListView.ItemsSource = _firewallRuleRows;
        PersistenceListView.ItemsSource = _persistenceRows;
        QuarantineListView.ItemsSource = _quarantineRows;
        VaultListView.ItemsSource = _vaultRows;

        // Restore historical events, quarantine, and vault asynchronously so window startup never blocks UI thread
        RefreshVirusDbStatusUi();
        _ = LoadInitialDashboardDataAsync();

        _onEventRecordedHandler = evt =>
        {
            Dispatcher.BeginInvoke(() =>
            {
                _allEventRows.Insert(0, new SecurityEventRow(evt));
                while (_allEventRows.Count > 1000) _allEventRows.RemoveAt(_allEventRows.Count - 1);
                ApplyEventFilter();
                if (evt.ActionTaken is SecurityActionTaken.Quarantined or SecurityActionTaken.QuarantinePendingReboot or SecurityActionTaken.QuarantineCopyOnly)
                {
                    RefreshQuarantineList();
                }
                else
                {
                    RefreshDashboardCounters();
                }
            });
        };
        _orchestrator.EventRecorded += _onEventRecordedHandler;

        _onEngineStatusHandler = msg =>
        {
            Dispatcher.BeginInvoke(() => FooterMessageText.Text = msg);
        };
        _orchestrator.EngineStatusMessage += _onEngineStatusHandler;

        _onDatabaseUpdatedHandler = msg =>
        {
            Dispatcher.BeginInvoke(() =>
            {
                RefreshVirusDbStatusUi();
                FooterMessageText.Text = msg;
            });
        };
        _orchestrator.DatabaseUpdated += _onDatabaseUpdatedHandler;

        LoadPolicyIntoUi();
        RefreshEngineStateUi();
        _ = RefreshHardeningStatusAsync();

        // Zero-polling Win32 event hooks for Clipboard (WM_CLIPBOARDUPDATE) and USB arrival (WM_DEVICECHANGE).
        // Ensures 0 idle UI wakeups even when running minimized in the system tray!
        AttachZeroPollingWin32Hooks();
    }

    private async Task LoadInitialDashboardDataAsync()
    {
        try
        {
            var (pastEvents, qEntries, vEntries) = await Task.Run(() => (
                _orchestrator.AuditLog.LoadRecentEvents(150),
                _orchestrator.Quarantine.ListEntries(),
                _orchestrator.Vault.ListSnapshots()));

            foreach (var past in pastEvents)
            {
                _allEventRows.Add(new SecurityEventRow(past));
            }
            _quarantineRows.Clear();
            foreach (var q in qEntries) _quarantineRows.Add(new QuarantineRow(q));
            _vaultRows.Clear();
            foreach (var v in vEntries) _vaultRows.Add(new VaultSnapshotRow(v));

            ApplyEventFilter();
            RefreshDashboardCounters();
        }
        catch { }
    }

    private void AttachZeroPollingWin32Hooks()
    {
        try
        {
            var hwnd = new WindowInteropHelper(this).EnsureHandle();
            _hwndSource = HwndSource.FromHwnd(hwnd);
            if (_hwndSource is not null)
            {
                _hwndSource.AddHook(WndProcHook);
                if (AddClipboardFormatListener(hwnd))
                {
                    _registeredHwnd = hwnd;
                }
            }
            Win32.SystemEvents.PowerModeChanged += OnPowerModeChanged;
        }
        catch { }
    }

    private void OnPowerModeChanged(object? sender, Win32.PowerModeChangedEventArgs e)
    {
        if (e.Mode == Win32.PowerModes.StatusChange)
        {
            Dispatcher.BeginInvoke(RefreshEngineStateUi);
        }
    }

    private IntPtr WndProcHook(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == WM_CLIPBOARDUPDATE)
        {
            Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background, CheckClipboardSafely);
        }
        else if (msg == WM_DEVICECHANGE && wParam == new IntPtr(DBT_DEVICEARRIVAL))
        {
            _orchestrator.NotifyUsbDeviceArrival();
        }
        return IntPtr.Zero;
    }

    private void CheckClipboardSafely()
    {
        if (!_orchestrator.IsRunning || !_orchestrator.CurrentPolicy.EnableClipboardGuard) return;
        try
        {
            if (!System.Windows.Clipboard.ContainsText()) return;
            var text = System.Windows.Clipboard.GetText();
            if (string.IsNullOrWhiteSpace(text) || text.Length > 16384) return;
            if (string.Equals(text, _lastClipboardSample, StringComparison.Ordinal)) return;
            _lastClipboardSample = text;
            _orchestrator.InspectClipboardText(text);
        }
        catch
        {
            // Ignore transient clipboard lock by another process.
        }
    }

    private async void OnRunSelfTestClick(object sender, RoutedEventArgs e)
    {
        var btn = sender as UIElement;
        if (btn is not null) btn.IsEnabled = false;
        try
        {
            FooterMessageText.Text = "15대 보안 방어력 자체 레드팀 검증 실행 중...";
            var checks = await Task.Run(SecuritySelfTestRunner.RunAllSafeChecks);
            int passed = checks.Count(c => c.Passed);
            var sb = new StringBuilder();
            sb.AppendLine($"AegisSentinel v7.0 자체 보안 방어력 검증 결과: {passed} / {checks.Count} 통과\n");
            foreach (var c in checks)
            {
                sb.AppendLine($"{(c.Passed ? "[PASS]" : "[FAIL]")} {c.Name} — {c.Detail}");
            }

            FooterMessageText.Text = $"15대 방어력 자체 검증 완료: {passed}/{checks.Count} 통과";
            System.Windows.MessageBox.Show(sb.ToString(), "AegisSentinel v7.0 자체 방어 검증", MessageBoxButton.OK,
                passed == checks.Count ? MessageBoxImage.Information : MessageBoxImage.Warning);
        }
        catch (Exception ex)
        {
            FooterMessageText.Text = $"자체 검증 오류: {ex.Message}";
        }
        finally
        {
            if (btn is not null) btn.IsEnabled = true;
        }
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (!AllowClose)
        {
            e.Cancel = true;
            Hide();
            return;
        }
        try { _scanCts?.Cancel(); } catch { }
        if (_onEventRecordedHandler is not null) _orchestrator.EventRecorded -= _onEventRecordedHandler;
        if (_onEngineStatusHandler is not null) _orchestrator.EngineStatusMessage -= _onEngineStatusHandler;
        if (_onDatabaseUpdatedHandler is not null) _orchestrator.DatabaseUpdated -= _onDatabaseUpdatedHandler;
        try { Win32.SystemEvents.PowerModeChanged -= OnPowerModeChanged; } catch { }
        if (_registeredHwnd != IntPtr.Zero)
        {
            _ = RemoveClipboardFormatListener(_registeredHwnd);
            _registeredHwnd = IntPtr.Zero;
        }
        _hwndSource?.RemoveHook(WndProcHook);
        base.OnClosing(e);
    }

    private void OnNavSelected(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded || sender is not System.Windows.Controls.RadioButton rb) return;
        var tag = rb.Tag?.ToString() ?? "Dashboard";

        ViewDashboard.Visibility = tag == "Dashboard" ? Visibility.Visible : Visibility.Collapsed;
        ViewThreats.Visibility = tag == "Threats" ? Visibility.Visible : Visibility.Collapsed;
        ViewScanner.Visibility = tag == "Scanner" ? Visibility.Visible : Visibility.Collapsed;
        ViewNetwork.Visibility = tag == "Network" ? Visibility.Visible : Visibility.Collapsed;
        ViewPersistence.Visibility = tag == "Persistence" ? Visibility.Visible : Visibility.Collapsed;
        ViewVault.Visibility = tag == "Vault" ? Visibility.Visible : Visibility.Collapsed;
        ViewSandbox.Visibility = tag == "Sandbox" ? Visibility.Visible : Visibility.Collapsed;
        ViewHardening.Visibility = tag == "Hardening" ? Visibility.Visible : Visibility.Collapsed;

        (PageHeaderTitle.Text, PageHeaderSubtitle.Text) = tag switch
        {
            "Threats" => ("실시간 위협 피드", " — MITRE ATT&CK · 상관분석 · 포렌식 상세"),
            "Scanner" => ("바이러스 검사 · MZK 치료", " — 6단계 MZK 정밀검사 · 시그니처 · 브라우저/HOSTS/레지스트리 원클릭 복구"),
            "Network" => ("네트워크 · 커널 방화벽", " — 외부 TCP 연결 · DNS 도메인 · WFP 규칙"),
            "Persistence" => ("지속성 감사 (Autoruns)", " — 7대 Windows 자동실행 벡터 실시간 점검"),
            "Vault" => ("자동 복구 금고 · 격리소", " — 랜섬웨어 원본 복원 및 악성 파일 격리 관리"),
            "Sandbox" => ("제로트러스트 격리 실행기", " — 프로필 격리 및 Windows Sandbox 가상화"),
            "Hardening" => ("커널 보안 · IOC 정책", " — Defender CFA · 5대 ASR 규칙 · 위협 인텔리전스"),
            _ => ("커맨드 센터", " — 9중 엔드포인트 방어 실시간 현황")
        };

        if (tag == "Scanner")
        {
            RefreshVirusDbStatusUi();
        }
        else if (tag == "Network")
        {
            _ = RefreshNetworkConnectionsAsync();
            _ = RefreshFirewallRulesAsync();
        }
        else if (tag == "Persistence")
        {
            _ = RefreshPersistenceAsync();
        }
        else if (tag == "Vault")
        {
            RefreshVaultList();
            RefreshQuarantineList();
        }
        else if (tag == "Hardening")
        {
            _ = RefreshHardeningStatusAsync();
        }
    }

    private void OnGoToThreatsClick(object sender, RoutedEventArgs e)
    {
        NavThreats.IsChecked = true;
    }

    public void RefreshEngineStateUi()
    {
        bool running = _orchestrator.IsRunning;
        bool elevated = ProcessController.IsCurrentProcessElevated();
        bool etw = _orchestrator.IsEtwKernelModeActive;
        bool etwDns = _orchestrator.IsEtwDnsModeActive;

        AppEditionSubtitleText.Text = elevated ? "Enterprise Guard v7.0 (Admin)" : "Enterprise Guard v7.0 (User Mode)";
        StatusBadgeText.Text = running ? "실시간 통합 방어 작동 중" : "보호 일시 중지됨";
        StatusBadgeBorder.Background = running ? BrushBadgeActiveBg : BrushBadgePausedBg;
        StatusBadgeText.Foreground = running ? BrushBadgeActiveFg : BrushBadgePausedFg;

        var powerNote = PowerProfileHelper.IsOnBatteryPower ? " · 배터리 절전" : string.Empty;
        TelemetryBadgeText.Text = (etw
            ? (etwDns ? "ETW 커널 + 실시간 DNS + 레지스트리 (Admin)" : "ETW 커널 텔레메트리 활성 (Admin)")
            : (elevated ? "관리자 모드" : "유저 모드 (ETW는 승격 필요)")) + powerNote;

        ElevateButton.Visibility = elevated ? Visibility.Collapsed : Visibility.Visible;
        ToggleEngineButton.Content = running ? "감시 일시중지" : "감시 재개";

        var p = _orchestrator.CurrentPolicy;
        SetEngineCardState(CardSupplyChainStatus, running && p.EnableProcessSupplyChainGuard);
        SetEngineCardState(CardRansomwareStatus, running && p.EnableRansomwareShield);
        SetEngineCardState(CardNetworkStatus, running && p.EnableNetworkGuard);
        SetEngineCardState(CardFilelessStatus, running && p.EnableFilelessScriptGuard);
        SetEngineCardState(CardMemoryStatus, running && p.EnableMemoryInjectionGuard);
        SetEngineCardState(CardCredentialStatus, running && p.EnableCredentialAndDllGuard);
        SetEngineCardState(CardPersistenceStatus, running && p.EnablePersistenceGuard);
        SetEngineCardState(CardDownloadUsbStatus, running && p.EnableDownloadAndUsbGuard);
        SetEngineCardState(CardVaultStatus, running && p.EnableAutoRecoveryVault);
    }

    private static void SetEngineCardState(TextBlock label, bool active)
    {
        label.Text = active ? "활성" : "비활성";
        label.Foreground = active ? BrushCardActiveFg : BrushCardInactiveFg;
    }

    private void RefreshDashboardCounters()
    {
        _recentDashboardRows.Clear();
        foreach (var row in _allEventRows.Take(8))
        {
            _recentDashboardRows.Add(row);
        }

        DashboardEventSummaryText.Text = $"이벤트: {_allEventRows.Count}건 | 금고: {_vaultRows.Count}개 | 격리: {_quarantineRows.Count}건 | 커스텀 규칙: {_orchestrator.CustomRules.ActiveRuleCount}개 | ATT&CK: {MitreAttackCatalog.GetAllCoveredTechniques().Count}기법";
    }

    private void ApplyEventFilter()
    {
        var severityTag = (SeverityFilterCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "ALL";
        var search = EventSearchBox?.Text?.Trim() ?? string.Empty;

        _filteredEventRows.Clear();
        foreach (var row in _allEventRows)
        {
            bool sevOk = severityTag switch
            {
                "Critical" => row.Source.Severity == ThreatSeverity.Critical,
                "High" => row.Source.Severity >= ThreatSeverity.High,
                "Medium" => row.Source.Severity >= ThreatSeverity.Medium,
                _ => true
            };
            if (!sevOk) continue;

            if (!string.IsNullOrWhiteSpace(search))
            {
                bool match = row.SummaryText.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                             row.ProcessText.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                             row.MitreText.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                             row.CategoryText.Contains(search, StringComparison.OrdinalIgnoreCase);
                if (!match) continue;
            }

            _filteredEventRows.Add(row);
        }
    }

    private void OnEventFilterChanged(object sender, SelectionChangedEventArgs e)
    {
        if (IsLoaded) ApplyEventFilter();
    }

    private void OnEventSearchChanged(object sender, TextChangedEventArgs e)
    {
        if (IsLoaded) ApplyEventFilter();
    }

    private void OnEventSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (EventsListView.SelectedItem is not SecurityEventRow row) return;
        var ev = row.Source;
        ev.EnsureMitrePopulated();

        var sb = new StringBuilder();
        sb.AppendLine($"[{ev.Severity}] {ev.Title}  |  MITRE: {ev.MitreTechniqueId} ({ev.MitreTactic})  |  위험도: {ev.RiskScore}/100");
        sb.AppendLine($"설명     : {ev.Description}");
        if (!string.IsNullOrWhiteSpace(ev.ProcessAncestry)) sb.AppendLine($"실행 계보: {ev.ProcessAncestry}");
        if (!string.IsNullOrWhiteSpace(ev.ProcessPath)) sb.AppendLine($"실행 경로: {ev.ProcessPath}");
        if (!string.IsNullOrWhiteSpace(ev.CommandLine)) sb.AppendLine($"명령줄   : {ev.CommandLine}");
        if (!string.IsNullOrWhiteSpace(ev.RemoteEndpoint)) sb.AppendLine($"외부 연결: {ev.RemoteEndpoint} ({ev.RemoteDomain})");
        if (ev.RiskSignals.Count > 0) sb.AppendLine($"위험 신호: {string.Join(", ", ev.RiskSignals)}");
        EventInspectorText.Text = sb.ToString();
    }

    private void LoadPolicyIntoUi()
    {
        _suppressUiEvents = true;
        try
        {
            var policy = _orchestrator.CurrentPolicy;
            foreach (ComboBoxItem item in ModeComboBox.Items)
            {
                if (string.Equals(item.Tag?.ToString(), policy.Mode.ToString(), StringComparison.OrdinalIgnoreCase))
                {
                    ModeComboBox.SelectedItem = item;
                    break;
                }
            }

            LowFrictionCheckBox.IsChecked = policy.SmartLowFrictionMode;
            ProtectedFoldersBox.Text = string.Join(Environment.NewLine, policy.ProtectedFolders);
            WatchedLaunchersBox.Text = string.Join(Environment.NewLine, policy.WatchedLauncherProcesses);
            WhitelistPathsBox.Text = string.Join(Environment.NewLine, policy.WhitelistedExecutablePaths);
            VirusTotalKeyBox.Text = policy.VirusTotalApiKey;
            AutoStartCheckBox.IsChecked = WindowsSecurityHardening.IsAutoStartEnabled();

            var intel = _orchestrator.ThreatIntel.GetSnapshot();
            BlockedDomainsBox.Text = string.Join(Environment.NewLine, intel.BlockedDomains);
            BlockedIpsBox.Text = string.Join(Environment.NewLine, intel.BlockedIpAddresses);
            BlockedHashesBox.Text = string.Join(Environment.NewLine, intel.BlockedSha256Hashes);
            RefreshThreatFeedStatusUi(intel);
        }
        finally
        {
            _suppressUiEvents = false;
        }
    }

    private void RefreshThreatFeedStatusUi(ThreatIntelDatabase? snapshot = null)
    {
        var intel = snapshot ?? _orchestrator.ThreatIntel.GetSnapshot();
        int totalIps = _orchestrator.ThreatIntel.TotalBlockedIpCount;
        int totalDoms = _orchestrator.ThreatIntel.TotalBlockedDomainCount;
        ThreatFeedStatusText.Text = intel.LastFeedSyncUtc.HasValue
            ? $"글로벌 피드: C2 IP {totalIps:N0} · 도메인 {totalDoms:N0} (동기화: {intel.LastFeedSyncUtc.Value.ToLocalTime():MM-dd HH:mm})"
            : $"글로벌 피드 미동기화 (사용자 IOC: IP {intel.BlockedIpAddresses.Count} · 도메인 {intel.BlockedDomains.Count})";
    }

    public void RefreshAfterIntervention()
    {
        EventsListView.Items.Refresh();
        DashboardRecentListView.Items.Refresh();
        RefreshQuarantineList();

        // Merge any newly whitelisted executable paths without erasing unsaved user edits in WhitelistPathsBox
        var currentLines = SplitLines(WhitelistPathsBox.Text);
        bool added = false;
        foreach (var path in _orchestrator.CurrentPolicy.WhitelistedExecutablePaths)
        {
            if (!currentLines.Contains(path, StringComparer.OrdinalIgnoreCase))
            {
                currentLines.Add(path);
                added = true;
            }
        }
        if (added)
        {
            WhitelistPathsBox.Text = string.Join(Environment.NewLine, currentLines);
        }
    }

    private void OnProtectionModeChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressUiEvents || ModeComboBox.SelectedItem is not ComboBoxItem item) return;
        if (Enum.TryParse<ProtectionMode>(item.Tag?.ToString(), out var mode))
        {
            var policy = _orchestrator.CurrentPolicy.Clone();
            policy.Mode = mode;
            _orchestrator.UpdatePolicy(policy);
            FooterMessageText.Text = $"보호 모드 변경됨: {mode}";
        }
    }

    private void OnLowFrictionToggled(object sender, RoutedEventArgs e)
    {
        if (_suppressUiEvents) return;
        var policy = _orchestrator.CurrentPolicy.Clone();
        policy.SmartLowFrictionMode = LowFrictionCheckBox.IsChecked == true;
        _orchestrator.UpdatePolicy(policy);
        FooterMessageText.Text = policy.SmartLowFrictionMode
            ? "스마트 저마찰 모드 켜짐 (단일 약한 신호는 조용히 관찰하고 복합 공격 시 즉시 차단)"
            : "민감 모드 켜짐 (중간 위험 신호에도 즉시 확인 창 표시)";
    }

    private void OnElevateClick(object sender, RoutedEventArgs e)
    {
        var exePath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(exePath)) return;
        try
        {
            Process.Start(new ProcessStartInfo { FileName = exePath, UseShellExecute = true, Verb = "runas" });
            if (System.Windows.Application.Current is App app) app.ExitApplication();
        }
        catch (Exception ex)
        {
            FooterMessageText.Text = $"관리자 권한 승격 취소/실패: {ex.Message}";
        }
    }

    private void OnToggleEngineClick(object sender, RoutedEventArgs e)
    {
        if (_orchestrator.IsRunning) _orchestrator.Stop();
        else _orchestrator.Start();
        RefreshEngineStateUi();
    }

    private void OnExportMitreLayerClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var path = _orchestrator.AuditLog.ExportMitreNavigatorLayer(
                _allEventRows.Select(r => r.Source).ToList());
            FooterMessageText.Text = $"MITRE ATT&CK Navigator v4.5 레이어 JSON 생성 완료: {path}";
            System.Windows.MessageBox.Show(
                $"MITRE ATT&CK Navigator(v4.5) 커버리지 JSON이 생성되었습니다.\n\n저장 경로:\n{path}\n\n" +
                $"포함된 탐지 기법: {MitreAttackCatalog.GetAllCoveredTechniques().Count}개\n" +
                "https://mitre-attack.github.io/attack-navigator/ 에서 Open Existing Layer로 바로 시각화할 수 있습니다.",
                "MITRE ATT&CK Navigator 내보내기",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            FooterMessageText.Text = $"ATT&CK 레이어 내보내기 실패: {ex.Message}";
            System.Windows.MessageBox.Show($"ATT&CK 레이어 생성 오류: {ex.Message}", "오류", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void OnExportHtmlReportClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var path = _orchestrator.AuditLog.ExportHtmlReport(
                _allEventRows.Select(r => r.Source).ToList(),
                _lastHardeningStatus,
                _orchestrator.Quarantine.ListEntries(),
                _orchestrator.Vault.ListSnapshots(),
                telemetry: _orchestrator.Metrics.GetSnapshot());

            FooterMessageText.Text = $"포렌식 HTML 리포트 생성 완료: {path}";
            try
            {
                Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
            }
            catch { }
        }
        catch (Exception ex)
        {
            FooterMessageText.Text = $"리포트 생성 실패: {ex.Message}";
            System.Windows.MessageBox.Show($"포렌식 리포트 생성 오류: {ex.Message}", "오류", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async void OnQuickScanFromHeaderClick(object sender, RoutedEventArgs e)
    {
        NavScanner.IsChecked = true;
        await RunMzkScanAsync(MalwareScanMode.MzkDeepScan);
    }

    private async void OnRunMzkDeepScanClick(object sender, RoutedEventArgs e)
    {
        await RunMzkScanAsync(MalwareScanMode.MzkDeepScan);
    }

    private async void OnRunQuickScanClick(object sender, RoutedEventArgs e)
    {
        await RunMzkScanAsync(MalwareScanMode.QuickScan);
    }

    private async void OnRunFullSystemScanClick(object sender, RoutedEventArgs e)
    {
        var confirm = System.Windows.MessageBox.Show(
            "전체 PC 정밀 검사는 모든 고정 드라이브(C:, D: 등)와 MZK 6단계 시스템 영역을 검사합니다.\n진행 중 언제든지 [검사 중지] 버튼으로 멈출 수 있습니다. 시작할까요?",
            "전체 PC 바이러스 정밀 검사",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);
        if (confirm != MessageBoxResult.Yes) return;

        await RunMzkScanAsync(MalwareScanMode.FullSystemScan);
    }

    private void OnCancelScanClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var cts = _scanCts;
            if (cts is not null && !cts.IsCancellationRequested)
            {
                cts.Cancel();
                ScanStatusText.Text = "작업 중지 요청 중...";
            }
        }
        catch (ObjectDisposedException) { }
    }

    private void SetScanControlsEnabled(bool enabled, bool canCancel = false)
    {
        HeaderQuickScanBtn.IsEnabled = enabled;
        MzkDeepScanBtn.IsEnabled = enabled;
        QuickScanBtn.IsEnabled = enabled;
        FullScanBtn.IsEnabled = enabled;
        FolderScanBtn.IsEnabled = enabled;
        FileScanBtn.IsEnabled = enabled;
        UpdateVirusDbBtn.IsEnabled = enabled;
        CureSelectedBtn.IsEnabled = enabled;
        SelectAllThreatsBtn.IsEnabled = enabled;
        UnselectAllThreatsBtn.IsEnabled = enabled;
        VirusTotalQueryBtn.IsEnabled = enabled;
        CancelScanBtn.IsEnabled = !enabled && canCancel;
    }

    private void RefreshVirusDbStatusUi()
    {
        var intel = _orchestrator.ThreatIntel;
        var hashes = intel.TotalBlockedHashCount;
        var domains = intel.TotalBlockedDomainCount;
        var ips = intel.TotalBlockedIpCount;
        var pups = _orchestrator.BrowserPupCleaner.ActivePupRuleCount;
        var updated = intel.HashDb.LastUpdatedUtc?.ToLocalTime().ToString("MM-dd HH:mm") ?? "미동기화";
        VirusDbStatusText.Text = $"DB: 악성 해시 {hashes:N0}개 · 애드웨어/멀웨어 도메인 {domains:N0}개 · C2 IP {ips:N0}개 · PUP {pups}종 (갱신: {updated})";
    }

    private async void OnUpdateVirusDbClick(object sender, RoutedEventArgs e)
    {
        if (_isScanning) return;
        _isScanning = true;
        var localCts = new CancellationTokenSource();
        _scanCts = localCts;
        bool completed = false;
        SetScanControlsEnabled(false, canCancel: true);
        ScanProgressBar.IsIndeterminate = false;
        ScanProgressBar.Value = 15;
        ScanStatusText.Text = "글로벌 초대형 바이러스·애드웨어 DB 다운로드 및 바이너리 인덱스 컴파일 중...";

        try
        {
            var progress = new Progress<string>(msg =>
            {
                if (completed) return;
                ScanStatusText.Text = msg;
                if (ScanProgressBar.Value < 90) ScanProgressBar.Value += 10;
            });

            var (hashRes, feedRes) = await _orchestrator.ThreatIntel.SyncFullAntivirusDatabaseAsync(
                abuseChAuthKey: null,
                progress: progress,
                ct: localCts.Token);

            completed = true;
            RefreshVirusDbStatusUi();
            ScanProgressBar.Value = 100;
            ScanStatusText.Text = $"{hashRes.Summary} | {feedRes.Summary}";
            FooterMessageText.Text = ScanStatusText.Text;

            System.Windows.MessageBox.Show(
                $"글로벌 바이러스·애드웨어 데이터베이스 업데이트가 완료되었습니다!\n\n" +
                $"• 악성 파일 SHA-256 바이너리 DB: {_orchestrator.ThreatIntel.TotalBlockedHashCount:N0}개 ({_orchestrator.ThreatIntel.HashDb.DatabaseSizeBytes / (1024.0 * 1024.0):F2} MB)\n" +
                $"• 애드웨어·멀웨어 차단 도메인 DB: {_orchestrator.ThreatIntel.TotalBlockedDomainCount:N0}개\n" +
                $"• 봇넷 C2 IP 차단 DB: {_orchestrator.ThreatIntel.TotalBlockedIpCount:N0}개\n" +
                $"• 국내 그리드/PUP 룰 DB: {_orchestrator.BrowserPupCleaner.ActivePupRuleCount}종\n\n" +
                "이제 [MZK 6단계 정밀 검사] 및 실시간 ETW 감시에 즉시 반영됩니다.",
                "AegisSentinel 바이러스 DB 업데이트 완료",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (OperationCanceledException)
        {
            completed = true;
            ScanProgressBar.Value = 0;
            ScanStatusText.Text = "사용자 요청으로 바이러스 DB 업데이트가 취소되었습니다 (기존 로컬 DB 유지).";
        }
        catch (Exception ex)
        {
            completed = true;
            ScanStatusText.Text = $"DB 업데이트 실패: {ex.Message}";
            System.Windows.MessageBox.Show($"DB 업데이트 오류: {ex.Message}", "오류", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            completed = true;
            if (ReferenceEquals(_scanCts, localCts)) _scanCts = null;
            localCts.Dispose();
            _isScanning = false;
            SetScanControlsEnabled(true);
        }
    }

    private async Task RunMzkScanAsync(MalwareScanMode mode, string? customTargetPath = null)
    {
        if (_isScanning) return;
        _isScanning = true;
        var localCts = new CancellationTokenSource();
        _scanCts = localCts;
        bool completed = false;
        SetScanControlsEnabled(false, canCancel: true);
        _scanFindingRows.Clear();
        ScanProgressBar.IsIndeterminate = false;
        ScanProgressBar.Value = 2;

        var modeTitle = mode switch
        {
            MalwareScanMode.MzkDeepScan => "MZK 6단계 정밀 검사",
            MalwareScanMode.FullSystemScan => "전체 PC 정밀 검사",
            MalwareScanMode.CustomFolderScan => $"폴더 정밀 검사 ({customTargetPath})",
            MalwareScanMode.SingleFileScan => $"단일 파일 검사 ({System.IO.Path.GetFileName(customTargetPath)})",
            _ => "빠른 바이러스 검사"
        };

        ScanStatusText.Text = $"{modeTitle} 시작 중...";
        ScanStageDetailText.Text = string.Empty;

        try
        {
            bool includeDefender = DefenderCrossCheckBox.IsChecked == true;
            var progress = new Progress<MzkScanProgress>(r =>
            {
                if (completed) return;
                ScanProgressBar.Value = r.PercentComplete;
                ScanStatusText.Text = $"[{r.StageIndex}/{r.TotalStages}] {r.StageName} — 검사 {r.ScannedItems:N0}건 | 탐지 {r.ThreatsFound}건 ({r.PercentComplete:F0}%)";
                ScanStageDetailText.Text = $"현재 대상: {r.CurrentTarget}";
            });

            var result = await _orchestrator.MzkScanner.RunScanAsync(
                mode,
                _orchestrator.CurrentPolicy,
                customTargetPath,
                includeDefender,
                progress,
                localCts.Token);

            completed = true;
            foreach (var f in result.Findings)
            {
                _scanFindingRows.Add(new ScanFindingRow(f));
            }

            ScanProgressBar.Value = 100;
            int threatCount = result.Findings.Count(f => f.RiskScore >= 40);
            var cancelNote = result.WasCancelled ? " (사용자 중지)" : string.Empty;
            ScanStatusText.Text = threatCount == 0
                ? $"{modeTitle} 완료{cancelNote} — 검사 {result.TotalScannedItems:N0}건 ({result.Duration.TotalSeconds:F1}초) | 바이러스·하이재킹 이상 없음!"
                : $"{modeTitle} 완료{cancelNote} — 검사 {result.TotalScannedItems:N0}건 ({result.Duration.TotalSeconds:F1}초) | 위협 {threatCount}건 발견 — 하단 [일괄 치료]로 복구하세요.";
            ScanStageDetailText.Text = string.Join("  ·  ", result.StageSummaries);
            FooterMessageText.Text = ScanStatusText.Text;
        }
        catch (Exception ex)
        {
            completed = true;
            ScanStatusText.Text = $"검사 중 오류 발생: {ex.Message}";
        }
        finally
        {
            completed = true;
            if (ReferenceEquals(_scanCts, localCts)) _scanCts = null;
            localCts.Dispose();
            _isScanning = false;
            SetScanControlsEnabled(true);
        }
    }

    private async void OnScanFolderClick(object sender, RoutedEventArgs e)
    {
        if (_isScanning) return;
        using var dlg = new WinForms.FolderBrowserDialog { Description = "바이러스 정밀 검사할 폴더 선택" };
        if (dlg.ShowDialog() != WinForms.DialogResult.OK) return;

        await RunMzkScanAsync(MalwareScanMode.CustomFolderScan, dlg.SelectedPath);
    }

    private async void OnScanSingleFileClick(object sender, RoutedEventArgs e)
    {
        if (_isScanning) return;
        var dlg = new Win32.OpenFileDialog { Title = "바이러스 정밀 검사할 파일 선택" };
        if (dlg.ShowDialog() != true) return;

        await RunMzkScanAsync(MalwareScanMode.SingleFileScan, dlg.FileName);
    }

    private void OnSelectAllThreatsClick(object sender, RoutedEventArgs e)
    {
        if (_isScanning) return;
        foreach (var row in _scanFindingRows)
        {
            if (row.CanCure)
            {
                row.IsSelected = true;
            }
        }
    }

    private void OnUnselectAllThreatsClick(object sender, RoutedEventArgs e)
    {
        if (_isScanning) return;
        foreach (var row in _scanFindingRows)
        {
            row.IsSelected = false;
        }
    }

    private async void OnCureSelectedThreatsClick(object sender, RoutedEventArgs e)
    {
        if (_isScanning) return;
        var selectedRows = _scanFindingRows.Where(r => r.IsSelected && r.CanCure).ToList();
        if (selectedRows.Count == 0)
        {
            System.Windows.MessageBox.Show(
                "치료할 위협 항목을 왼쪽 체크박스에서 선택해 주세요.",
                "MZK 치료 안내",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        var confirm = System.Windows.MessageBox.Show(
            $"선택한 {selectedRows.Count}건의 위협을 안전하게 치료·복구할까요?\n\n" +
            "• 악성 파일은 영구 삭제 대신 [AES-256-GCM 격리소]로 안전 이동됩니다 (복원 가능)\n" +
            "• HOSTS/브라우저 설정 변경 전 백업이 자동 생성됩니다\n" +
            "• Windows 핵심 시스템 파일과 핵심 서비스는 안전 가드레일에 의해 보호됩니다",
            "MZK 위협 일괄 치료 확인",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;

        _isScanning = true;
        SetScanControlsEnabled(false, canCancel: false);
        ScanProgressBar.IsIndeterminate = true;
        ScanStatusText.Text = $"선택한 {selectedRows.Count}건의 위협 치료 및 시스템 복구 진행 중...";

        try
        {
            var summary = await _orchestrator.Remediation.CureSelectedAsync(selectedRows.Select(r => r.Source));
            var map = summary.Results.ToDictionary(r => r.Item.Id);

            var sb = new StringBuilder();
            sb.AppendLine($"MZK 위협 치료 완료: 성공 {summary.Succeeded}건 / 실패 {summary.Failed}건\n");

            foreach (var row in selectedRows)
            {
                if (map.TryGetValue(row.Source.Id, out var res))
                {
                    row.StatusText = res.Success ? "치료 완료" : "치료 실패";
                    if (res.Success) row.IsSelected = false;
                    sb.AppendLine($"{(res.Success ? "[치료완료]" : "[실패]")} {row.ThreatName} — {res.Message}");
                }
            }

            RefreshQuarantineList();
            _ = RefreshPersistenceAsync();
            ScanStatusText.Text = $"MZK 치료 완료 — 성공 {summary.Succeeded}건 / 실패 {summary.Failed}건";
            FooterMessageText.Text = ScanStatusText.Text;

            System.Windows.MessageBox.Show(
                sb.ToString(),
                "AegisSentinel MZK 치료 리포트",
                MessageBoxButton.OK,
                summary.Failed == 0 ? MessageBoxImage.Information : MessageBoxImage.Warning);
        }
        catch (Exception ex)
        {
            ScanStatusText.Text = $"치료 중 오류 발생: {ex.Message}";
            System.Windows.MessageBox.Show($"치료 실패: {ex.Message}", "오류", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            ScanProgressBar.IsIndeterminate = false;
            ScanProgressBar.Value = 100;
            _isScanning = false;
            SetScanControlsEnabled(true);
        }
    }

    private async void OnQueryVirusTotalClick(object sender, RoutedEventArgs e)
    {
        if (ScanFindingsListView.SelectedItem is not ScanFindingRow row) return;
        if (!System.IO.File.Exists(row.FilePath))
        {
            System.Windows.MessageBox.Show("VirusTotal 조회는 디스크 파일 항목에서만 지원됩니다.", "안내", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var apiKey = _orchestrator.CurrentPolicy.VirusTotalApiKey;
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            System.Windows.MessageBox.Show(
                "VirusTotal 해시 조회를 사용하려면 [커널 보안 · IOC 정책] 탭에 무료 VirusTotal API Key를 입력 후 저장해 주세요. (파일 원본은 업로드하지 않고 SHA-256 해시만 조회합니다.)",
                "VirusTotal 조회", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        try
        {
            var sha = row.Source.Sha256;
            if (string.IsNullOrWhiteSpace(sha))
            {
                ScanStatusText.Text = $"SHA-256 해시 계산 중 ({System.IO.Path.GetFileName(row.FilePath)})...";
                sha = await Task.Run(() => SignatureVerifier.ComputeSha256Cached(row.FilePath));
            }

            var shortHash = sha.Length >= 16 ? sha[..16] : sha;
            ScanStatusText.Text = $"VirusTotal SHA-256 조회 중 ({shortHash}...)";
            var res = await ThreatIntelStore.QueryVirusTotalHashAsync(sha, apiKey);
            ScanStatusText.Text = res.Summary;
            System.Windows.MessageBox.Show($"{row.FilePath}\nSHA-256: {sha}\n\n{res.Summary}", "VirusTotal 결과", MessageBoxButton.OK,
                res.IsMalicious ? MessageBoxImage.Warning : MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            ScanStatusText.Text = $"VirusTotal 조회 오류: {ex.Message}";
        }
    }

    private async void OnRefreshNetworkClick(object sender, RoutedEventArgs e) => await RefreshNetworkConnectionsAsync();

    private async Task RefreshNetworkConnectionsAsync()
    {
        try
        {
            FooterMessageText.Text = "활성 외부 TCP 연결 및 디지털 서명 조회 중...";
            var conns = await Task.Run(() => _orchestrator.NetworkGuard.GetActiveExternalConnections());
            _connectionRows.Clear();
            foreach (var conn in conns)
            {
                _connectionRows.Add(new ConnectionRow(conn));
            }
            FooterMessageText.Text = $"활성 외부 TCP 연결 {_connectionRows.Count}건 조회됨";
        }
        catch (Exception ex)
        {
            FooterMessageText.Text = $"네트워크 연결 조회 오류: {ex.Message}";
        }
    }

    private async void OnBlockSelectedConnectionClick(object sender, RoutedEventArgs e)
    {
        if (ConnectionsListView.SelectedItem is not ConnectionRow row) return;
        if (string.IsNullOrWhiteSpace(row.ProcessPath))
        {
            FooterMessageText.Text = "선택한 연결의 실행 경로를 확인할 수 없습니다 (관리자 승격이 필요하거나 시스템 프로세스입니다).";
            return;
        }
        var btn = sender as UIElement;
        if (btn is not null) btn.IsEnabled = false;
        try
        {
            var (_, msg) = await FirewallController.BlockOutboundExecutableAsync(row.ProcessPath);
            FooterMessageText.Text = msg;
            await RefreshFirewallRulesAsync();
        }
        catch (Exception ex)
        {
            FooterMessageText.Text = $"방화벽 차단 오류: {ex.Message}";
        }
        finally
        {
            if (btn is not null) btn.IsEnabled = true;
        }
    }

    private async void OnRefreshFirewallRulesClick(object sender, RoutedEventArgs e) => await RefreshFirewallRulesAsync();

    private async Task RefreshFirewallRulesAsync()
    {
        try
        {
            var rules = await FirewallController.ListManagedBlockRulesAsync();
            _firewallRuleRows.Clear();
            foreach (var r in rules) _firewallRuleRows.Add(r);
        }
        catch (Exception ex)
        {
            FooterMessageText.Text = $"방화벽 규칙 조회 오류: {ex.Message}";
        }
    }

    private async void OnUnblockFirewallRuleClick(object sender, RoutedEventArgs e)
    {
        if (FirewallRulesListView.SelectedItem is not FirewallRuleInfo rule) return;
        var btn = sender as UIElement;
        if (btn is not null) btn.IsEnabled = false;
        try
        {
            var (_, msg) = await FirewallController.RemoveRuleByNameAsync(rule.RuleName);
            FooterMessageText.Text = msg;
            await RefreshFirewallRulesAsync();
        }
        catch (Exception ex)
        {
            FooterMessageText.Text = $"방화벽 규칙 해제 오류: {ex.Message}";
        }
        finally
        {
            if (btn is not null) btn.IsEnabled = true;
        }
    }

    private async void OnRefreshPersistenceClick(object sender, RoutedEventArgs e) => await RefreshPersistenceAsync();

    private async Task RefreshPersistenceAsync()
    {
        try
        {
            FooterMessageText.Text = "7종 지속성(Autoruns) 항목 스캔 중...";
            var entries = await Task.Run(() => _orchestrator.Persistence.GetFullPersistenceInventory());
            _persistenceRows.Clear();
            foreach (var entry in entries) _persistenceRows.Add(new PersistenceRow(entry));
            FooterMessageText.Text = $"지속성 항목 {_persistenceRows.Count}건 감사 완료";
        }
        catch (Exception ex)
        {
            FooterMessageText.Text = $"지속성 감사 오류: {ex.Message}";
        }
    }

    private async void OnRemovePersistenceEntryClick(object sender, RoutedEventArgs e)
    {
        if (PersistenceListView.SelectedItem is not PersistenceRow row) return;
        var confirm = System.Windows.MessageBox.Show(
            $"다음 지속성 항목을 제거하시겠습니까?\n\n분류: {row.Category}\n이름: {row.Name}\n위치: {row.SourceLocation}",
            "지속성 항목 제거", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;

        bool ok = PersistenceMonitor.TryRollbackEntry(row.SourceLocation, row.Name);
        var resultMsg = ok ? $"제거 완료: {row.Name}" : "제거 실패 (관리자 권한이 필요하거나 WMI/시스템 보호 항목입니다)";
        await RefreshPersistenceAsync();
        FooterMessageText.Text = resultMsg;
        if (!ok)
        {
            System.Windows.MessageBox.Show(resultMsg, "지속성 항목 제거", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async void OnFirewallBlockSelectedEventClick(object sender, RoutedEventArgs e)
    {
        if (EventsListView.SelectedItem is not SecurityEventRow row) return;
        var btn = sender as UIElement;
        if (btn is not null) btn.IsEnabled = false;
        try
        {
            var (_, msg) = await _orchestrator.FirewallBlockProcessAsync(row.Source);
            FooterMessageText.Text = msg;
            EventsListView.Items.Refresh();
            DashboardRecentListView.Items.Refresh();
        }
        catch (Exception ex)
        {
            FooterMessageText.Text = $"방화벽 차단 오류: {ex.Message}";
        }
        finally
        {
            if (btn is not null) btn.IsEnabled = true;
        }
    }

    private async void OnKillSelectedEventClick(object sender, RoutedEventArgs e)
    {
        if (EventsListView.SelectedItem is not SecurityEventRow row) return;
        var btn = sender as UIElement;
        if (btn is not null) btn.IsEnabled = false;
        try
        {
            var res = await Task.Run(() => _orchestrator.KillAndQuarantineDetailed(row.Source));
            EventsListView.Items.Refresh();
            DashboardRecentListView.Items.Refresh();
            RefreshQuarantineList();
            if (res.HasAnyPendingFrozenProcess)
            {
                FooterMessageText.Text = row.Source.ContainmentDetail;
                System.Windows.MessageBox.Show(
                    $"일부 동결된 프로세스 종료에 실패해 추적이 유지되었습니다.\n{row.Source.ContainmentDetail}",
                    "부분 종료 경고 (재시도 필요)",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
        }
        catch (Exception ex)
        {
            FooterMessageText.Text = $"종료/격리 오류: {ex.Message}";
        }
        finally
        {
            if (btn is not null) btn.IsEnabled = true;
        }
    }

    private void OnResumeSelectedEventClick(object sender, RoutedEventArgs e)
    {
        if (EventsListView.SelectedItem is not SecurityEventRow row) return;
        var res = _orchestrator.AllowAndResumeProcessDetailed(row.Source, addToWhitelist: true);
        RefreshAfterIntervention();
        if (res.HasAnyPendingRetry)
        {
            FooterMessageText.Text = row.Source.ContainmentDetail;
            System.Windows.MessageBox.Show(
                $"일부 프로세스 재개에 실패하여 동결 추적이 유지되었습니다.\n{row.Source.ContainmentDetail}",
                "부분 재개 (재시도 필요)",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
    }

    private void OnClearEventsClick(object sender, RoutedEventArgs e)
    {
        _allEventRows.Clear();
        ApplyEventFilter();
        RefreshDashboardCounters();
        RefreshVirusDbStatusUi();
    }

    private void RefreshVaultList()
    {
        _vaultRows.Clear();
        foreach (var entry in _orchestrator.Vault.ListSnapshots()) _vaultRows.Add(new VaultSnapshotRow(entry));
        RefreshDashboardCounters();
    }

    private async void OnSnapshotNowClick(object sender, RoutedEventArgs e)
    {
        var btn = sender as UIElement;
        if (btn is not null) btn.IsEnabled = false;
        try
        {
            FooterMessageText.Text = "보호 폴더 스냅샷 생성 중...";
            int count = await Task.Run(() => _orchestrator.Vault.SnapshotProtectedFolders(_orchestrator.CurrentPolicy.ProtectedFolders));
            RefreshVaultList();
            FooterMessageText.Text = $"복구 금고 스냅샷 완료: 신규/갱신 {count}개 (총 {_vaultRows.Count}개 보관 중)";
        }
        catch (Exception ex)
        {
            FooterMessageText.Text = $"스냅샷 생성 오류: {ex.Message}";
        }
        finally
        {
            if (btn is not null) btn.IsEnabled = true;
        }
    }

    private void OnRestoreVaultFileClick(object sender, RoutedEventArgs e)
    {
        if (VaultListView.SelectedItem is not VaultSnapshotRow row) return;
        try
        {
            if (_orchestrator.Vault.RestoreSnapshot(row.Source.Id))
            {
                FooterMessageText.Text = $"원본 복구 완료: {row.OriginalPath}";
                System.Windows.MessageBox.Show($"깨끗한 원본으로 복구되었습니다:\n{row.OriginalPath}", "자동 복구 금고", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                System.Windows.MessageBox.Show("원본 복구 실패: 파일이 다른 프로그램에서 잠겨 있거나 스냅샷이 손상되었습니다.", "자동 복구 금고", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show($"복구 실패 (파일이 다른 프로그램에서 열려 있는지 확인하세요):\n{ex.Message}", "복구 금고 오류", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void OnBrowseSandboxExeClick(object sender, RoutedEventArgs e)
    {
        var dlg = new Win32.OpenFileDialog { Filter = "실행 파일 (*.exe)|*.exe|모든 파일 (*.*)|*.*", Title = "격리 실행할 프로그램 선택" };
        if (dlg.ShowDialog() == true) SandboxExePathBox.Text = dlg.FileName;
    }

    private void OnLaunchIsolatedClick(object sender, RoutedEventArgs e)
    {
        var result = _sandboxLauncher.LaunchIsolatedWithJob(SandboxExePathBox.Text.Trim(), SandboxArgsBox.Text.Trim());
        SandboxResultText.Text = result.Success
            ? $"[성공] {result.Message}\n격리 프로필 경로: {result.SandboxProfileDirectory}"
            : $"[실패] {result.Message}";
    }

    private void OnLaunchWindowsSandboxClick(object sender, RoutedEventArgs e)
    {
        var target = SandboxExePathBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(target))
        {
            SandboxResultText.Text = "먼저 실행 파일 또는 폴더 경로를 지정하세요.";
            return;
        }

        try
        {
            var wsbPath = _sandboxLauncher.GenerateWindowsSandboxConfig(target, allowNetworking: true, readOnlyFolder: true);
            if (SandboxLauncher.IsWindowsSandboxAvailable())
            {
                Process.Start(new ProcessStartInfo(wsbPath) { UseShellExecute = true });
                SandboxResultText.Text = $"Windows Sandbox 실행됨: {wsbPath}";
            }
            else
            {
                SandboxResultText.Text = $"Windows Sandbox 기능이 꺼져 있어 설정 파일만 생성했습니다: {wsbPath}";
            }
        }
        catch (Exception ex)
        {
            SandboxResultText.Text = $"Windows Sandbox 실행 실패: {ex.Message}";
        }
    }

    private async void OnRefreshHardeningClick(object sender, RoutedEventArgs e) => await RefreshHardeningStatusAsync();

    private async Task RefreshHardeningStatusAsync()
    {
        try
        {
            var status = await WindowsSecurityHardening.GetStatusAsync();
            _lastHardeningStatus = status;

            SidebarScoreText.Text = $"{status.SecurityPostureScore}/100";
            SidebarScoreBar.Value = status.SecurityPostureScore;
            DashboardScoreBigText.Text = $"{status.SecurityPostureScore} / 100";
            ElevatedTaskBtn.Content = status.ElevatedScheduledTaskEnabled ? "등록됨 (해제)" : "등록하기";

            var foldersText = status.CfaProtectedFolders.Count > 0
                ? string.Join(", ", status.CfaProtectedFolders)
                : "(기본 시스템 폴더만 보호)";

            HardeningStatusSummaryText.Text =
                $"종합 OS 보안 점수              : {status.SecurityPostureScore} / 100\n" +
                $"현재 실행 권한                 : {(status.IsElevated ? "관리자 (ETW 커널 텔레메트리 활성)" : "일반 사용자")}\n" +
                $"무-UAC 관리자 자동실행 작업    : {(status.ElevatedScheduledTaskEnabled ? "등록됨 (부팅 즉시 ETW 활성)" : "미등록")}\n" +
                $"Defender 실시간 보호           : {(status.DefenderRealTimeEnabled ? "켜짐 (정상)" : "꺼짐/확인불가")}\n" +
                $"Defender 변조 방지 (Tamper)    : {(status.TamperProtectionEnabled ? "켜짐 (안전)" : "꺼짐 (권장)")}\n" +
                $"Defender 커널 폴더 보호 (CFA)  : {(status.ControlledFolderAccessEnabled ? "켜짐 (Ring-0 랜섬웨어 차단)" : "꺼짐 (활성화 권장)")}\n" +
                $"Defender 네트워크 / PUA 보호   : {(status.NetworkProtectionEnabled ? "네트워크 ON" : "네트워크 OFF")} | {(status.PuaProtectionEnabled ? "PUA ON" : "PUA OFF")}\n" +
                $"Enterprise ASR 공격표면감소    : {status.ActiveAsrRuleCount} / {WindowsSecurityHardening.RecommendedAsrRules.Length} 규칙 활성\n" +
                $"코어 격리 메모리 무결성 (HVCI) : {(status.MemoryIntegrityHvciEnabled ? "켜짐" : "꺼짐 (Windows 보안에서 켜기 권장)")}\n" +
                $"Windows LSA 보호 (RunAsPPL)    : {(status.LsaProtectionEnabled ? "켜짐" : "꺼짐")}\n" +
                $"PowerShell 스크립트 로깅(4104) : {(status.ScriptBlockLoggingEnabled ? "켜짐 (파일리스 감시)" : "꺼짐 (활성화 권장)")}\n" +
                $"CFA 등록 보호 폴더             : {foldersText}" +
                (string.IsNullOrWhiteSpace(status.ErrorMessage) ? "" : $"\n참고: {status.ErrorMessage}");
        }
        catch (Exception ex)
        {
            FooterMessageText.Text = $"보안 상태 조회 오류: {ex.Message}";
        }
    }

    private async void OnEnableHardeningAuditClick(object sender, RoutedEventArgs e)
    {
        var btn = sender as UIElement;
        if (btn is not null) btn.IsEnabled = false;
        try
        {
            var (ok, msg) = await WindowsSecurityHardening.EnableDefenderKernelHardeningAsync(
                _orchestrator.CurrentPolicy.ProtectedFolders, enableScriptBlockLogging: true, enableAsrRules: true, asrAuditOnly: true);
            FooterMessageText.Text = msg;
            if (!ok) System.Windows.MessageBox.Show(msg, "Windows 커널 보안 연동", MessageBoxButton.OK, MessageBoxImage.Warning);
            await RefreshHardeningStatusAsync();
        }
        catch (Exception ex)
        {
            FooterMessageText.Text = $"커널 보안 설정 오류: {ex.Message}";
        }
        finally
        {
            if (btn is not null) btn.IsEnabled = true;
        }
    }

    private async void OnEnableHardeningBlockClick(object sender, RoutedEventArgs e)
    {
        var btn = sender as UIElement;
        if (btn is not null) btn.IsEnabled = false;
        try
        {
            var (ok, msg) = await WindowsSecurityHardening.EnableDefenderKernelHardeningAsync(
                _orchestrator.CurrentPolicy.ProtectedFolders, enableScriptBlockLogging: true, enableAsrRules: true, asrAuditOnly: false);
            FooterMessageText.Text = msg;
            if (!ok) System.Windows.MessageBox.Show(msg, "Windows 커널 보안 연동", MessageBoxButton.OK, MessageBoxImage.Warning);
            await RefreshHardeningStatusAsync();
        }
        catch (Exception ex)
        {
            FooterMessageText.Text = $"커널 보안 설정 오류: {ex.Message}";
        }
        finally
        {
            if (btn is not null) btn.IsEnabled = true;
        }
    }

    private async void OnHardenAclsClick(object sender, RoutedEventArgs e)
    {
        var btn = sender as UIElement;
        if (btn is not null) btn.IsEnabled = false;
        try
        {
            var (ok, msg) = await WindowsSecurityHardening.HardenCredentialFolderAclsAsync(_orchestrator.Vault.VaultDirectory);
            FooterMessageText.Text = msg;
            System.Windows.MessageBox.Show(msg, "NTFS 권한 잠금", MessageBoxButton.OK,
                ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
        }
        catch (Exception ex)
        {
            FooterMessageText.Text = $"NTFS 권한 잠금 오류: {ex.Message}";
        }
        finally
        {
            if (btn is not null) btn.IsEnabled = true;
        }
    }

    private async void OnToggleElevatedTaskClick(object sender, RoutedEventArgs e)
    {
        var btn = sender as UIElement;
        if (btn is not null) btn.IsEnabled = false;
        try
        {
            var exePath = Environment.ProcessPath ?? string.Empty;
            bool currentlyEnabled = _lastHardeningStatus?.ElevatedScheduledTaskEnabled == true;
            var (_, msg) = await WindowsSecurityHardening.SetElevatedAutoStartTaskAsync(!currentlyEnabled, exePath);
            FooterMessageText.Text = msg;
            await RefreshHardeningStatusAsync();
        }
        catch (Exception ex)
        {
            FooterMessageText.Text = $"자동 실행 작업 설정 오류: {ex.Message}";
        }
        finally
        {
            if (btn is not null) btn.IsEnabled = true;
        }
    }

    private void OnAutoStartToggled(object sender, RoutedEventArgs e)
    {
        if (_suppressUiEvents) return;
        var exePath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(exePath)) return;
        bool enabled = AutoStartCheckBox.IsChecked == true;
        bool ok = WindowsSecurityHardening.SetAutoStart(enabled, exePath);
        FooterMessageText.Text = ok
            ? (enabled ? "로그인 시 일반 자동 실행 등록됨" : "로그인 시 일반 자동 실행 해제됨")
            : "자동 실행 설정 변경 실패";
    }

    private async void OnSyncThreatFeedsClick(object sender, RoutedEventArgs e)
    {
        await SyncThreatFeedsAsync(silent: false);
    }

    private async Task SyncThreatFeedsAsync(bool silent)
    {
        SyncThreatFeedsBtn.IsEnabled = false;
        ThreatFeedStatusText.Text = "Abuse.ch(Feodo Tracker · URLhaus) 글로벌 위협 피드 동기화 중...";
        try
        {
            var result = await _orchestrator.ThreatIntel.SyncPublicThreatFeedsAsync();
            RefreshThreatFeedStatusUi();
            FooterMessageText.Text = result.Summary;
            if (!silent)
            {
                System.Windows.MessageBox.Show(result.Summary, "글로벌 위협 인텔리전스(IOC) 동기화",
                    MessageBoxButton.OK, result.Success ? MessageBoxImage.Information : MessageBoxImage.Warning);
            }
        }
        catch (Exception ex)
        {
            ThreatFeedStatusText.Text = $"피드 동기화 오류: {ex.Message}";
        }
        finally
        {
            SyncThreatFeedsBtn.IsEnabled = true;
        }
    }

    private void OnSavePolicyClick(object sender, RoutedEventArgs e)
    {
        var policy = _orchestrator.CurrentPolicy.Clone();
        policy.ProtectedFolders = SplitLines(ProtectedFoldersBox.Text);
        policy.WatchedLauncherProcesses = SplitLines(WatchedLaunchersBox.Text);
        policy.WhitelistedExecutablePaths = SplitLines(WhitelistPathsBox.Text);
        policy.VirusTotalApiKey = VirusTotalKeyBox.Text.Trim();

        _orchestrator.ThreatIntel.UpdateDatabase(
            SplitLines(BlockedHashesBox.Text),
            SplitLines(BlockedIpsBox.Text),
            SplitLines(BlockedDomainsBox.Text));

        _orchestrator.UpdatePolicy(policy);
        RefreshEngineStateUi();
        FooterMessageText.Text = "보호 정책 및 위협 인텔리전스(IOC) 목록이 저장되어 즉시 반영되었습니다.";
    }

    private void RefreshQuarantineList()
    {
        _quarantineRows.Clear();
        foreach (var entry in _orchestrator.Quarantine.ListEntries()) _quarantineRows.Add(new QuarantineRow(entry));
        RefreshDashboardCounters();
    }

    private void OnRefreshQuarantineClick(object sender, RoutedEventArgs e) => RefreshQuarantineList();

    internal static QuarantineRestoreResult ExecuteRestoreWithConflictConfirmation(
        QuarantineManager quarantine,
        string entryId,
        Func<string, bool> confirmOverwrite)
    {
        var res = quarantine.RestoreFileDetailed(entryId, overwriteExisting: false);
        if (res.Status == QuarantineRestoreStatus.DestinationConflict && confirmOverwrite(res.DestinationPath))
        {
            res = quarantine.RestoreFileDetailed(entryId, overwriteExisting: true);
        }
        return res;
    }

    private void OnRestoreQuarantineClick(object sender, RoutedEventArgs e)
    {
        if (QuarantineListView.SelectedItem is not QuarantineRow row) return;
        try
        {
            bool userDeclinedConflict = false;
            var res = ExecuteRestoreWithConflictConfirmation(
                _orchestrator.Quarantine,
                row.Source.Id,
                destPath =>
                {
                    var confirm = System.Windows.MessageBox.Show(
                        $"복원 대상 경로에 이미 파일이 존재합니다:\n{destPath}\n\n" +
                        "기존 파일을 덮어쓰고 격리된 원본으로 교체할까요?\n" +
                        "('아니오'를 선택하면 기존 파일과 격리 사본이 모두 안전하게 유지됩니다.)",
                        "격리 파일 복원 충돌 확인",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Warning);
                    if (confirm != MessageBoxResult.Yes)
                    {
                        userDeclinedConflict = true;
                        return false;
                    }
                    return true;
                });

            if (userDeclinedConflict)
            {
                FooterMessageText.Text = "복원 취소됨: 대상 경로의 기존 파일과 격리 사본을 보존했습니다.";
                return;
            }

            if (res.Success)
            {
                FooterMessageText.Text = $"복원 완료: {row.OriginalPath}";
                RefreshQuarantineList();
            }
            else
            {
                if (res.Status == QuarantineRestoreStatus.RestoredButRebootDeleteCancelFailed)
                {
                    RefreshQuarantineList();
                    FooterMessageText.Text = "복원 경고: 재부팅 삭제 예약 취소 실패 — 격리 사본 보존됨";
                }
                System.Windows.MessageBox.Show($"격리 파일 복원 실패: {res.Message}", "격리소 오류", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show($"복원 실패: {ex.Message}", "격리소 오류", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void OnDeleteQuarantineClick(object sender, RoutedEventArgs e)
    {
        if (QuarantineListView.SelectedItem is not QuarantineRow row) return;
        try
        {
            if (_orchestrator.Quarantine.DeletePermanently(row.Source.Id))
            {
                FooterMessageText.Text = $"영구 삭제 완료: {row.OriginalPath}";
                RefreshQuarantineList();
            }
            else
            {
                FooterMessageText.Text = "이미 삭제되었거나 접근할 수 없는 격리 항목입니다.";
            }
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show($"영구 삭제 실패: {ex.Message}", "격리소 오류", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private static List<string> SplitLines(string text)
    {
        return text
            .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
            .Select(s => s.Trim())
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}
