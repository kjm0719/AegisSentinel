using System.Drawing;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using AegisSentinel.Core.Engine;
using AegisSentinel.Core.Models;
using WinForms = System.Windows.Forms;

namespace AegisSentinel.App;

public partial class App : System.Windows.Application, IDisposable
{
    private const int MaxQueuedPrompts = 32;
    private ThreatPromptWindow? _activePrompt;
    private ThreatPromptQueueCoordinator? _promptCoordinator;
    private Mutex? _singleInstanceMutex;
    private bool _ownsMutex;
    private bool _cleanedUp;
    private WinForms.NotifyIcon? _trayIcon;
    private SecurityOrchestrator? _orchestrator;
    private MainWindow? _mainWindow;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        InstallGlobalExceptionGuards();
        SessionEnding += (_, _) =>
        {
            if (_mainWindow is not null) _mainWindow.AllowClose = true;
            CleanupResources();
        };

        bool createdNew = false;
        try
        {
            _singleInstanceMutex = new Mutex(true, "AegisSentinel_SingleInstance_Guard", out createdNew);
            _ownsMutex = createdNew;
        }
        catch (UnauthorizedAccessException)
        {
            // Another elevated instance already holds the mutex
            createdNew = false;
        }
        catch (AbandonedMutexException)
        {
            createdNew = true;
            _ownsMutex = true;
        }
        if (!createdNew)
        {
            System.Windows.MessageBox.Show(
                "AegisSentinel이 이미 백그라운드(시스템 트레이)에서 실행 중입니다.",
                "AegisSentinel",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            Shutdown();
            return;
        }

        _orchestrator = new SecurityOrchestrator();
        _promptCoordinator = new ThreatPromptQueueCoordinator(
            MaxQueuedPrompts,
            showPrompt: ShowSinglePrompt,
            updateActiveQueuedCount: count => _activePrompt?.UpdateQueuedCount(count),
            releaseSuspendedEvent: evt =>
            {
                if (_orchestrator is not null && evt.HasAnySuspendedProcess)
                {
                    try { _orchestrator.AllowAndResumeProcess(evt, addToWhitelist: false, grantSessionImmunity: false); } catch { }
                }
            });
        _mainWindow = new MainWindow(_orchestrator);
        MainWindow = _mainWindow;

        SetupTrayIcon();

        _orchestrator.EventRecorded += evt =>
        {
            if (evt.Severity < ThreatSeverity.High) return;

            Dispatcher.BeginInvoke(() =>
            {
                if (_cleanedUp || _orchestrator is null) return;
                if (_mainWindow is { IsVisible: false })
                {
                    _trayIcon?.ShowBalloonTip(
                        4000,
                        $"AegisSentinel [{evt.MitreTechniqueId}] {evt.Severity}",
                        $"{evt.Title} ({evt.ProcessName})",
                        WinForms.ToolTipIcon.Warning);
                }
            });
        };

        _orchestrator.UserInterventionRequired += evt =>
        {
            Dispatcher.BeginInvoke(() =>
            {
                if (_cleanedUp || _orchestrator is null) return;
                EnqueueOrShowPrompt(evt);
            });
        };

        _orchestrator.Start();
        _mainWindow.RefreshEngineStateUi();

        bool startMinimized = e.Args.Any(a => a.Equals("--minimized", StringComparison.OrdinalIgnoreCase));
        if (!startMinimized)
        {
            _mainWindow.Show();
        }
        else
        {
            _trayIcon?.ShowBalloonTip(
                3000,
                "AegisSentinel 9중 보안 가드 시작",
                "백그라운드에서 공급망·랜섬웨어·네트워크·파일리스 공격을 실시간 감시 중입니다.",
                WinForms.ToolTipIcon.Info);
        }
    }

    private void SetupTrayIcon()
    {
        var menu = new WinForms.ContextMenuStrip();
        menu.Items.Add("커맨드 센터 열기", null, (_, _) => ShowMainWindow());
        menu.Items.Add("모니터링 일시 중지/재개", null, (_, _) => ToggleProtection());
        menu.Items.Add(new WinForms.ToolStripSeparator());
        menu.Items.Add("완전 종료", null, (_, _) => ExitApplication());

        _trayIcon = new WinForms.NotifyIcon
        {
            Icon = SystemIcons.Shield,
            Visible = true,
            Text = "AegisSentinel - 9중 실시간 보안 감시 중",
            ContextMenuStrip = menu
        };

        _trayIcon.DoubleClick += (_, _) => ShowMainWindow();
    }

    public void ShowMainWindow()
    {
        if (_mainWindow is null) return;
        _mainWindow.Show();
        if (_mainWindow.WindowState == WindowState.Minimized)
        {
            _mainWindow.WindowState = WindowState.Normal;
        }
        _mainWindow.Activate();
    }

    private void ToggleProtection()
    {
        if (_orchestrator is null) return;

        if (_orchestrator.IsRunning)
        {
            CloseAllOpenPrompts();
            _orchestrator.Stop();
            if (_trayIcon is not null) _trayIcon.Text = "AegisSentinel - 모니터링 일시 중지됨";
        }
        else
        {
            _orchestrator.Start();
            if (_trayIcon is not null) _trayIcon.Text = "AegisSentinel - 9중 실시간 보안 감시 중";
        }

        _mainWindow?.RefreshEngineStateUi();
    }

    private void EnqueueOrShowPrompt(SecurityEvent evt)
    {
        if (_orchestrator is null || _cleanedUp || _promptCoordinator is null) return;
        _promptCoordinator.EnqueueOrShow(evt);
        _activePrompt?.RefreshSuspensionDisplay();
    }

    private void ShowSinglePrompt(SecurityEvent evt)
    {
        if (_orchestrator is null || _cleanedUp) return;
        // Keep Owner = null and ShowActivated = False so minimizing MainWindow never hides the alert
        // and the popup never steals keyboard focus mid-typing!
        var prompt = new ThreatPromptWindow(_orchestrator, evt, _promptCoordinator?.QueuedCount ?? 0);
        _activePrompt = prompt;
        prompt.Closed += (_, _) =>
        {
            if (ReferenceEquals(_activePrompt, prompt))
            {
                _activePrompt = null;
            }
            _mainWindow?.RefreshAfterIntervention();
            if (!_cleanedUp && _orchestrator is not null)
            {
                _promptCoordinator?.OnActivePromptClosed(evt);
            }
        };
        prompt.Show();
    }

    private void CloseAllOpenPrompts()
    {
        // Drain queued events first so no suspended root OR child process is left stranded frozen
        _promptCoordinator?.DrainAllQueued();
        _promptCoordinator?.ClearActiveWithoutClosing();

        var active = _activePrompt;
        _activePrompt = null;
        if (active is not null)
        {
            try { active.Close(); } catch { }
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        CleanupResources();
        base.OnExit(e);
    }

    public void ExitApplication()
    {
        CloseAllOpenPrompts();
        if (_mainWindow is not null)
        {
            _mainWindow.AllowClose = true;
            _mainWindow.Close();
        }

        CleanupResources();
        Shutdown();
    }

    private void CleanupResources()
    {
        if (_cleanedUp) return;
        _cleanedUp = true;

        CloseAllOpenPrompts();
        _orchestrator?.Dispose();
        _orchestrator = null;

        if (_trayIcon is not null)
        {
            _trayIcon.Visible = false;
            _trayIcon.ContextMenuStrip?.Dispose();
            _trayIcon.Dispose();
            _trayIcon = null;
        }

        if (_ownsMutex && _singleInstanceMutex is not null)
        {
            try { _singleInstanceMutex.ReleaseMutex(); } catch { }
            _ownsMutex = false;
        }
        _singleInstanceMutex?.Dispose();
        _singleInstanceMutex = null;
    }

    private void InstallGlobalExceptionGuards()
    {
        DispatcherUnhandledException += (_, args) =>
        {
            LogRuntimeError("UI-Dispatcher", args.Exception);
            args.Handled = true;
        };

        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            LogRuntimeError("Background-Task", args.Exception);
            args.SetObserved();
        };

        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            if (args.ExceptionObject is Exception ex)
            {
                LogRuntimeError("AppDomain-Fatal", ex);
            }
            // Guarantee no user process stays frozen if the app ever crashes fatally
            try { CleanupResources(); } catch { }
        };
    }

    private static void LogRuntimeError(string source, Exception ex)
    {
        try
        {
            var logDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "AegisSentinel",
                "Logs");
            Directory.CreateDirectory(logDir);
            var line = $"[{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss}] [{source}] {ex.GetType().Name}: {ex.Message}{Environment.NewLine}";
            File.AppendAllText(Path.Combine(logDir, "runtime_errors.log"), line);
        }
        catch { }
    }

    public void Dispose()
    {
        CleanupResources();
        GC.SuppressFinalize(this);
    }
}
