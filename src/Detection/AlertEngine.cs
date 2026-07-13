using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Wraith.Models;

namespace Wraith.Detection
{
    public class AlertEngine
    {
        private const int FocusThreshold = 5;
        private const int LogWriteThreshold = 10;
        private const int ThreadThreshold = 15;
        private const int AuditApiCallThreshold = 3;
        private const double PeriodicMinInterval = 5.0;
        private const double PeriodicMaxInterval = 30.0;
        private const double PeriodicMaxVariance = 3.0;
        private const int DllInjectionThreshold = 3;
        private const int DllInjectionWindowSec = 30;
        private const int ClipboardThreshold = 5;
        private const int NamedPipeThreshold = 3;

        public List<AlertEvent> Evaluate(ProcessTracker tracker)
        {
            var alerts = new List<AlertEvent>();
            var now = DateTime.Now;

            foreach (var proc in tracker.GetAllProcesses())
            {
                if (proc.HasVisibleWindow)
                    continue;

                if (SystemProcessFilter.IsSystemProcess(proc.Name, proc.Path))
                    continue;

                if (proc.FocusEventCount >= FocusThreshold && !proc.AlertedNoWindowFocus)
                {
                    proc.AlertedNoWindowFocus = true;
                    alerts.Add(new AlertEvent
                    {
                        Timestamp = now,
                        PID = proc.PID,
                        ProcessName = proc.Name,
                        Severity = AlertSeverity.High,
                        Type = DetectionType.NoWindowFocusApi,
                        Message = $"No-window process: {proc.FocusEventCount} Win32k focus events"
                    });
                }

                if (proc.LogFilesOpened.Count > 0 &&
                    proc.LogFileWriteCount >= LogWriteThreshold &&
                    !proc.AlertedNoWindowLogWrites)
                {
                    proc.AlertedNoWindowLogWrites = true;
                    var files = string.Join(", ",
                        proc.LogFilesOpened.Select(f => Path.GetFileName(f)));
                    alerts.Add(new AlertEvent
                    {
                        Timestamp = now,
                        PID = proc.PID,
                        ProcessName = proc.Name,
                        Severity = AlertSeverity.Medium,
                        Type = DetectionType.NoWindowLogWrites,
                        Message = $"No-window process writing to log files: {files} ({proc.LogFileWriteCount} writes)"
                    });
                }

                if (proc.LogFileWriteTimestamps.Count >= 5 && !proc.AlertedPeriodicWrites)
                {
                    var intervals = new List<double>();
                    for (int i = 1; i < proc.LogFileWriteTimestamps.Count; i++)
                    {
                        intervals.Add((proc.LogFileWriteTimestamps[i] -
                            proc.LogFileWriteTimestamps[i - 1]).TotalSeconds);
                    }

                    if (intervals.Count >= 4)
                    {
                        var avg = intervals.Average();
                        var variance = intervals.Average(v => Math.Abs(v - avg));

                        if (avg >= PeriodicMinInterval &&
                            avg <= PeriodicMaxInterval &&
                            variance < PeriodicMaxVariance)
                        {
                            proc.AlertedPeriodicWrites = true;
                            alerts.Add(new AlertEvent
                            {
                                Timestamp = now,
                                PID = proc.PID,
                                ProcessName = proc.Name,
                                Severity = AlertSeverity.Medium,
                                Type = DetectionType.PeriodicFileWrites,
                                Message = $"Periodic log writes: ~every {avg:F1}s (variance {variance:F1}s) -- buffered write pattern"
                            });
                        }
                    }
                }

                if (proc.AuditApiCallCount >= AuditApiCallThreshold &&
                    !proc.AlertedAuditApiCall)
                {
                    proc.AlertedAuditApiCall = true;
                    alerts.Add(new AlertEvent
                    {
                        Timestamp = now,
                        PID = proc.PID,
                        ProcessName = proc.Name,
                        Severity = AlertSeverity.High,
                        Type = DetectionType.AuditApiCallNoWindow,
                        Message = $"No-window process: {proc.AuditApiCallCount} Win32k API audit calls (possible SetWindowsHookEx)"
                    });
                }

                if (proc.ThreadCreateCount >= ThreadThreshold &&
                    !proc.AlertedThreadInjection)
                {
                    proc.AlertedThreadInjection = true;
                    alerts.Add(new AlertEvent
                    {
                        Timestamp = now,
                        PID = proc.PID,
                        ProcessName = proc.Name,
                        Severity = AlertSeverity.Medium,
                        Type = DetectionType.ThreadInjection,
                        Message = $"No-window process created {proc.ThreadCreateCount} threads (potential injection activity)"
                    });
                }

                if (proc.SuspiciousDllLoadCount >= DllInjectionThreshold &&
                    !proc.AlertedDllInjection)
                {
                    var recent = proc.DllLoads
                        .Where(d => d.IsSuspicious && (now - d.Timestamp).TotalSeconds <= DllInjectionWindowSec)
                        .ToList();

                    if (recent.Count >= DllInjectionThreshold)
                    {
                        proc.AlertedDllInjection = true;
                        var dlls = string.Join(", ",
                            recent.Take(3).Select(d => Path.GetFileName(d.DllPath)));
                        alerts.Add(new AlertEvent
                        {
                            Timestamp = now,
                            PID = proc.PID,
                            ProcessName = proc.Name,
                            Severity = AlertSeverity.High,
                            Type = DetectionType.DllInjection,
                            Message = $"DLL injection: {recent.Count} suspicious DLL loads in {DllInjectionWindowSec}s ({dlls})"
                        });
                    }
                }

                if (proc.RegistryWrites.Count > 0 && !proc.AlertedRegistryPersistence)
                {
                    var persistenceWrites = proc.RegistryWrites
                        .Where(r => r.IsPersistenceKey)
                        .ToList();

                    if (persistenceWrites.Count > 0)
                    {
                        proc.AlertedRegistryPersistence = true;
                        var keys = string.Join(", ",
                            persistenceWrites.Take(2).Select(r => r.KeyPath));
                        alerts.Add(new AlertEvent
                        {
                            Timestamp = now,
                            PID = proc.PID,
                            ProcessName = proc.Name,
                            Severity = AlertSeverity.High,
                            Type = DetectionType.RegistryPersistence,
                            Message = $"Registry persistence: wrote to {persistenceWrites.Count} persistence key(s): {keys}"
                        });
                    }
                }

                if (proc.ClipboardReadCount >= ClipboardThreshold &&
                    !proc.AlertedClipboardAccess)
                {
                    proc.AlertedClipboardAccess = true;
                    alerts.Add(new AlertEvent
                    {
                        Timestamp = now,
                        PID = proc.PID,
                        ProcessName = proc.Name,
                        Severity = AlertSeverity.Medium,
                        Type = DetectionType.ClipboardAccess,
                        Message = $"Clipboard monitoring: {proc.ClipboardReadCount} clipboard reads from headless process"
                    });
                }

                if (proc.NamedPipeCount >= NamedPipeThreshold &&
                    !proc.AlertedNamedPipe)
                {
                    proc.AlertedNamedPipe = true;
                    var pipes = string.Join(", ",
                        proc.NamedPipes.Take(3).Select(p => p));
                    alerts.Add(new AlertEvent
                    {
                        Timestamp = now,
                        PID = proc.PID,
                        ProcessName = proc.Name,
                        Severity = AlertSeverity.Medium,
                        Type = DetectionType.NamedPipe,
                        Message = $"Named pipe activity: {proc.NamedPipeCount} pipe operations ({pipes})"
                    });
                }
            }

            return alerts;
        }
    }
}
