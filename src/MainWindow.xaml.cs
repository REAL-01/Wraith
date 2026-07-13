using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Wraith.Detection;
using Wraith.Etw;
using Wraith.Models;
using Microsoft.Win32;

namespace Wraith
{
    public partial class MainWindow : Window
    {
        private ProcessTracker _tracker;
        private WindowScanner _windowScanner;
        private AlertEngine _alertEngine;
        private EtwSessionManager _etwManager;
        private ProcessSnapshotter _snapshotter;
        private TaskManagerWatcher _tmWatcher;

        private Timer _windowTimer;
        private Timer _alertTimer;
        private Timer _snapshotTimer;
        private Timer _statsTimer;

        private DateTime _startTime;
        private int _alertCount;
        private int _eventCount;
        private bool _monitoring;
        private bool _verbose = true;

        private readonly ObservableCollection<EventLogViewModel> _events = new ObservableCollection<EventLogViewModel>();
        private readonly ObservableCollection<ProcessViewModel> _suspicious = new ObservableCollection<ProcessViewModel>();
        private readonly ObservableCollection<AlertViewModel> _alerts = new ObservableCollection<AlertViewModel>();
        private readonly object _lock = new object();

        private const int MaxEvents = 500;

        public MainWindow()
        {
            InitializeComponent();
            EventList.ItemsSource = _events;
            SuspiciousList.ItemsSource = _suspicious;
            AlertList.ItemsSource = _alerts;
        }

        private bool IsAdministrator()
        {
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        private void BtnStart_Click(object sender, RoutedEventArgs e)
        {
            if (!IsAdministrator())
            {
                var result = MessageBox.Show(
                    "Administrator privileges are required for ETW kernel sessions.\n\nRestart as Administrator?",
                    "Elevation Required",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);
                if (result == MessageBoxResult.Yes)
                {
                    try
                    {
                        var exePath = Process.GetCurrentProcess().MainModule.FileName;
                        var psi = new ProcessStartInfo
                        {
                            FileName = exePath,
                            UseShellExecute = true,
                            Verb = "runas"
                        };
                        Process.Start(psi);
                        Application.Current.Shutdown();
                    }
                    catch { }
                }
                return;
            }

            StartMonitoring();
        }

        private void StartMonitoring()
        {
            _tracker = new ProcessTracker();
            _windowScanner = new WindowScanner();
            _alertEngine = new AlertEngine();
            _snapshotter = new ProcessSnapshotter();
            _tmWatcher = new TaskManagerWatcher();
            _tmWatcher.OnEvasiveProcessDetected += OnTmEvasionDetected;
            _tmWatcher.OnTaskManagerStateChanged += OnTmStateChanged;
            _startTime = DateTime.Now;
            _alertCount = 0;
            _eventCount = 0;

            Dispatcher.Invoke(() =>
            {
                _events.Clear();
                _suspicious.Clear();
                _alerts.Clear();
                BtnStart.IsEnabled = false;
                BtnStop.IsEnabled = true;
                BtnExport.IsEnabled = true;
                StatusDot.Fill = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(0x3f, 0xb9, 0x50));
                StatusText.Text = "MONITORING";
                StatusText.Foreground = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(0x3f, 0xb9, 0x50));
                StatusBar.Text = "Initializing ETW sessions...";
            });

            _etwManager = new EtwSessionManager(_tracker);
            _etwManager.OnEvent = OnEtwEvent;
            _etwManager.OnError = msg => Dispatcher.Invoke(() =>
            {
                AddEvent(DateTime.Now, EtwEventType.ProcessStop, 0, "ERROR", msg, "#f85149");
                StatusBar.Text = "Error: " + msg;
            });
            _etwManager.OnStatus = msg => Dispatcher.Invoke(() =>
            {
                AddEvent(DateTime.Now, EtwEventType.ProcessStart, 0, "STATUS", msg, "#3fb950");
                StatusBar.Text = msg;
            });

            bool started = _etwManager.Start();

            _monitoring = true;

            _windowTimer = new Timer(_ => SafeScan(), null, 0, 3000);
            _alertTimer = new Timer(_ => SafeEvaluate(), null, 5000, 5000);
            _snapshotTimer = new Timer(_ => SafeSnapshot(), null, 1000, 2000);
            _statsTimer = new Timer(_ => SafeStats(), null, 1000, 1000);

            Dispatcher.Invoke(() =>
            {
                if (started)
                    StatusBar.Text = "Monitoring active.";
                else
                    StatusBar.Text = "Partial monitoring -- some ETW sessions failed.";
            });
        }

        private void BtnStop_Click(object sender, RoutedEventArgs e)
        {
            StopMonitoring();
        }

        private void StopMonitoring()
        {
            _monitoring = false;

            _windowTimer?.Dispose();
            _alertTimer?.Dispose();
            _snapshotTimer?.Dispose();
            _statsTimer?.Dispose();

            _etwManager?.Stop();
            _etwManager?.Dispose();

            Dispatcher.Invoke(() =>
            {
                BtnStart.IsEnabled = true;
                BtnStop.IsEnabled = false;
                StatusDot.Fill = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(0x48, 0x4f, 0x58));
                StatusText.Text = "IDLE";
                StatusText.Foreground = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(0x8b, 0x94, 0x9e));
                StatusBar.Text = "Monitoring stopped.";
            });
        }

        private void OnEtwEvent(EtwEventLog ev)
        {
            Interlocked.Increment(ref _eventCount);
            if (!_verbose) return;

            Dispatcher.BeginInvoke(() =>
            {
                AddEvent(ev.Timestamp, ev.Type, ev.PID, ev.ProcessName, ev.Detail, GetEventColor(ev.Type));
            });
        }

        private void AddEvent(DateTime ts, EtwEventType type, int pid, string name, string detail, string color)
        {
            var vm = new EventLogViewModel
            {
                TimeStr = ts.ToString("HH:mm:ss.fff"),
                TypeTag = GetEventTag(type),
                PidStr = pid > 0 ? $"PID={pid}" : "",
                Name = name.Length > 18 ? name.Substring(0, 18) : name,
                Detail = detail.Length > 80 ? "..." + detail.Substring(detail.Length - 77) : detail,
                Color = color
            };
            _events.Add(vm);
            while (_events.Count > MaxEvents)
                _events.RemoveAt(0);

            if (_events.Count > 0)
                EventList.ScrollIntoView(_events[_events.Count - 1]);
        }

        private string GetEventTag(EtwEventType type)
        {
            return type switch
            {
                EtwEventType.ProcessStart  => "PROC START ",
                EtwEventType.ProcessStop   => "PROC STOP  ",
                EtwEventType.ThreadStart   => "THRD START ",
                EtwEventType.FileOpen      => "FILE OPEN  ",
                EtwEventType.FileWrite     => "FILE WRITE ",
                EtwEventType.Win32kFocus   => "W32K FOCUS ",
                EtwEventType.Win32kApiCall => "W32K API   ",
                EtwEventType.TmEvasion     => "TM  EVASION",
                _                           => "???????????"
            };
        }

        private string GetEventColor(EtwEventType type)
        {
            return type switch
            {
                EtwEventType.ProcessStart   => "#58a6ff",
                EtwEventType.ProcessStop    => "#484f58",
                EtwEventType.ThreadStart    => "#8b949e",
                EtwEventType.FileOpen       => "#d2a8ff",
                EtwEventType.FileWrite      => "#d2a8ff",
                EtwEventType.Win32kFocus    => "#d29922",
                EtwEventType.Win32kApiCall  => "#f85149",
                EtwEventType.TmEvasion      => "#f85149",
                _                            => "#8b949e"
            };
        }

        private void OnTmEvasionDetected(int pid, string name, string reason, AlertSeverity severity)
        {
            Interlocked.Increment(ref _alertCount);

            Dispatcher.BeginInvoke(() =>
            {
                AddEvent(DateTime.Now, EtwEventType.TmEvasion, pid, name, reason, "#f85149");

                var sevColor = severity switch
                {
                    AlertSeverity.High   => "#f85149",
                    AlertSeverity.Medium => "#d29922",
                    _                     => "#8b949e"
                };

                var alertVm = new AlertViewModel
                {
                    TimeStr = DateTime.Now.ToString("HH:mm:ss"),
                    SeverityText = severity.ToString().ToUpper(),
                    SeverityColor = sevColor,
                    PID = pid,
                    ProcessName = name,
                    Message = reason,
                    Type = DetectionType.TaskManagerEvasion
                };
                _alerts.Insert(0, alertVm);

                var procVm = new ProcessViewModel
                {
                    PID = pid,
                    Name = name,
                    Reason = reason,
                    SeverityColor = sevColor,
                    IsSuspicious = true,
                    FirstDetected = DateTime.Now
                };
                var existing = _suspicious.FirstOrDefault(p => p.PID == pid);
                if (existing != null)
                {
                    existing.Reason = reason;
                    existing.SeverityColor = sevColor;
                }
                else
                {
                    _suspicious.Insert(0, procVm);
                }

                UpdateCounts();
            });
        }

        private void OnTmStateChanged(string msg)
        {
            Dispatcher.BeginInvoke(() =>
            {
                if (msg.Contains("opened"))
                {
                    StatTm.Text = "OPEN";
                    StatTm.Foreground = new System.Windows.Media.SolidColorBrush(
                        System.Windows.Media.Color.FromRgb(0xd2, 0x99, 0x22));
                }
                else if (msg.Contains("closed"))
                {
                    StatTm.Text = "--";
                    StatTm.Foreground = new System.Windows.Media.SolidColorBrush(
                        System.Windows.Media.Color.FromRgb(0x8b, 0x94, 0x9e));
                }
                StatTmStatus.Text = msg;
                StatusBar.Text = msg;
            });
        }

        private void SafeScan()
        {
            if (!_monitoring) return;
            try
            {
                var windowMap = _windowScanner.Scan();
                _tracker.UpdateWindowInfo(windowMap);
            }
            catch { }
        }

        private void SafeEvaluate()
        {
            if (!_monitoring) return;
            try
            {
                var alerts = _alertEngine.Evaluate(_tracker);
                foreach (var alert in alerts)
                {
                    Interlocked.Increment(ref _alertCount);
                    Dispatcher.BeginInvoke(() =>
                    {
                        var sevColor = alert.Severity switch
                        {
                            AlertSeverity.High   => "#f85149",
                            AlertSeverity.Medium => "#d29922",
                            _                     => "#8b949e"
                        };

                        var alertVm = new AlertViewModel
                        {
                            TimeStr = alert.Timestamp.ToString("HH:mm:ss"),
                            SeverityText = alert.Severity.ToString().ToUpper(),
                            SeverityColor = sevColor,
                            PID = alert.PID,
                            ProcessName = alert.ProcessName,
                            Message = alert.Message,
                            Type = alert.Type
                        };
                        _alerts.Insert(0, alertVm);

                        var procVm = new ProcessViewModel
                        {
                            PID = alert.PID,
                            Name = alert.ProcessName,
                            Reason = alert.Message,
                            SeverityColor = sevColor,
                            IsSuspicious = true,
                            FirstDetected = alert.Timestamp
                        };
                        var existing = _suspicious.FirstOrDefault(p => p.PID == alert.PID);
                        if (existing != null)
                        {
                            existing.Reason = alert.Message;
                            existing.SeverityColor = sevColor;
                        }
                        else
                        {
                            var snap = _snapshotter?.GetProcess(alert.PID);
                            if (snap != null)
                            {
                                procVm.Path = snap.Path;
                                procVm.MemMB = snap.WorkingSet64 / 1048576.0;
                            }
                            _suspicious.Insert(0, procVm);
                        }

                        UpdateCounts();
                    });
                }
            }
            catch { }
        }

        private void SafeSnapshot()
        {
            if (!_monitoring) return;
            try
            {
                var snapshots = _snapshotter.Snapshot();
                _tmWatcher.CheckSnapshots(snapshots);
            }
            catch { }
        }

        private void SafeStats()
        {
            if (!_monitoring) return;
            try
            {
                var uptime = DateTime.Now - _startTime;
                Dispatcher.BeginInvoke(() =>
                {
                    StatProcs.Text = _tracker?.Count.ToString() ?? "0";
                    StatAlerts.Text = _alertCount.ToString();
                    StatEvents.Text = _eventCount.ToString();
                    StatUptime.Text = uptime.ToString(@"hh\:mm\:ss");
                    UpdateCounts();
                });
            }
            catch { }
        }

        private void UpdateCounts()
        {
            AlertCount.Text = _alerts.Count.ToString();
            SuspiciousCount.Text = _suspicious.Count.ToString();
        }

        private void KillProcess_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is int pid)
                KillProcessByPid(pid);
        }

        private void KillAlertProcess_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is int pid)
                KillProcessByPid(pid);
        }

        private void KillProcessByPid(int pid)
        {
            var proc = _suspicious.FirstOrDefault(p => p.PID == pid);
            var name = proc?.Name ?? $"PID {pid}";

            var result = MessageBox.Show(
                $"Terminate process '{name}' (PID {pid})?\n\nThis will forcefully kill the process.",
                "Confirm Termination",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);
            if (result != MessageBoxResult.Yes) return;

            bool killed = false;
            try { killed = _snapshotter.KillProcess(pid); }
            catch { }

            Dispatcher.BeginInvoke(() =>
            {
                if (killed)
                {
                    AddEvent(DateTime.Now, EtwEventType.ProcessStop, pid, name, "Process terminated by user", "#3fb950");
                    StatusBar.Text = $"Process '{name}' (PID {pid}) terminated.";

                    var alertToRemove = _alerts.FirstOrDefault(a => a.PID == pid);
                    if (alertToRemove != null)
                    {
                        alertToRemove.IsActive = false;
                        _alerts.Remove(alertToRemove);
                    }
                    var procToRemove = _suspicious.FirstOrDefault(p => p.PID == pid);
                    if (procToRemove != null)
                        _suspicious.Remove(procToRemove);
                    UpdateCounts();
                }
                else
                {
                    MessageBox.Show($"Failed to terminate process '{name}' (PID {pid}).\nAccess may be denied.",
                        "Termination Failed", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            });
        }

        private void DismissAlert_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is AlertViewModel alert)
            {
                _alerts.Remove(alert);
                UpdateCounts();
            }
        }

        private void BtnExport_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new SaveFileDialog
            {
                Filter = "Text Report|*.txt|CSV Export|*.csv",
                FileName = $"wraith_report_{DateTime.Now:yyyyMMdd_HHmmss}.txt",
                DefaultExt = ".txt"
            };
            if (dlg.ShowDialog() != true) return;

            try
            {
                using var sw = new StreamWriter(dlg.FileName);
                sw.WriteLine("================================================================");
                sw.WriteLine("  WRAITH -- THREAT DETECTION REPORT");
                sw.WriteLine($"  Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                sw.WriteLine($"  Uptime:    {(DateTime.Now - _startTime):hh\\:mm\\:ss}");
                sw.WriteLine($"  Events:    {_eventCount}");
                sw.WriteLine($"  Alerts:    {_alertCount}");
                sw.WriteLine("================================================================");
                sw.WriteLine();

                sw.WriteLine("-- SUSPICIOUS PROCESSES --");
                foreach (var p in _suspicious)
                {
                    sw.WriteLine($"  PID={p.PID,-6}  {p.Name,-25}  {p.Reason}");
                    if (!string.IsNullOrEmpty(p.Path))
                        sw.WriteLine($"           Path: {p.Path}");
                }
                sw.WriteLine();

                sw.WriteLine("-- ALERTS --");
                foreach (var a in _alerts)
                {
                    sw.WriteLine($"  [{a.SeverityText}] {a.TimeStr}  PID={a.PID,-6}  {a.ProcessName,-20}  {a.Message}");
                }
                sw.WriteLine();

                sw.WriteLine("-- RECENT EVENTS (last 500) --");
                foreach (var ev in _events)
                {
                    sw.WriteLine($"  {ev.TimeStr}  {ev.TypeTag}  {ev.PidStr,-10}  {ev.Name,-18}  {ev.Detail}");
                }

                sw.WriteLine("================================================================");
                sw.WriteLine("  END OF REPORT");
                sw.WriteLine("================================================================");

                StatusBar.Text = $"Report exported to {dlg.FileName}";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Export failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void BtnClear_Click(object sender, RoutedEventArgs e)
        {
            _events.Clear();
            StatusBar.Text = "Event log cleared.";
        }

        private void TitleBar_MouseDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (e.ChangedButton == System.Windows.Input.MouseButton.Left)
                DragMove();
        }

        private void BtnMinimize_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void BtnClose_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            StopMonitoring();
        }
    }
}
