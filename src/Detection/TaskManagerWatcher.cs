using System;
using System.Collections.Generic;
using System.Linq;
using Wraith.Models;

namespace Wraith.Detection
{
    public class TaskManagerWatcher
    {
        private bool _tmWasOpen;
        private Dictionary<int, ProcessSnapshot> _preTmSnapshot;
        private List<int> _disappearedPids = new List<int>();
        private Dictionary<int, ProcessSnapshot> _disappearedInfo = new Dictionary<int, ProcessSnapshot>();
        private DateTime _tmOpenedAt;
        private int _selfPid = Environment.ProcessId;

        public event Action<int, string, string, AlertSeverity> OnEvasiveProcessDetected;
        public event Action<string> OnTaskManagerStateChanged;

        public void CheckSnapshots(List<ProcessSnapshot> current)
        {
            bool tmRunning = current.Any(p =>
                p.Name.Equals("taskmgr", StringComparison.OrdinalIgnoreCase));

            if (tmRunning && !_tmWasOpen)
            {
                _tmWasOpen = true;
                _tmOpenedAt = DateTime.Now;
                _preTmSnapshot = current.ToDictionary(p => p.PID);
                _disappearedPids.Clear();
                _disappearedInfo.Clear();
                OnTaskManagerStateChanged?.Invoke("Task Manager opened -- monitoring for evasive processes");
            }
            else if (!tmRunning && _tmWasOpen)
            {
                _tmWasOpen = false;
                OnTaskManagerStateChanged?.Invoke("Task Manager closed -- checking for reappeared processes");

                foreach (var pid in _disappearedPids.ToList())
                {
                    if (_disappearedInfo.TryGetValue(pid, out var info))
                    {
                        if (SystemProcessFilter.IsSystemProcess(info.Name, info.Path))
                            continue;
                    }

                    var reappeared = current.FirstOrDefault(p => p.PID == pid);
                    if (reappeared != null)
                    {
                        OnEvasiveProcessDetected?.Invoke(
                            pid,
                            reappeared.Name,
                            "Process terminated when Task Manager opened and restarted after it closed",
                            AlertSeverity.High);
                    }
                    else
                    {
                        if (_disappearedInfo.TryGetValue(pid, out var info2))
                        {
                            var elapsed = (DateTime.Now - _tmOpenedAt).TotalSeconds;
                            if (elapsed < 2)
                            {
                                OnEvasiveProcessDetected?.Invoke(
                                    pid,
                                    info2.Name,
                                    "Process terminated immediately when Task Manager opened",
                                    AlertSeverity.High);
                            }
                        }
                    }
                }
                _disappearedPids.Clear();
                _disappearedInfo.Clear();
            }
            else if (tmRunning && _tmWasOpen)
            {
                foreach (var kvp in _preTmSnapshot)
                {
                    int pid = kvp.Key;
                    if (pid == _selfPid) continue;
                    if (SystemProcessFilter.IsSystemProcess(kvp.Value.Name, kvp.Value.Path))
                        continue;

                    if (!current.Any(p => p.PID == pid) && !_disappearedPids.Contains(pid))
                    {
                        _disappearedPids.Add(pid);
                        _disappearedInfo[pid] = kvp.Value;
                        OnEvasiveProcessDetected?.Invoke(
                            pid,
                            kvp.Value.Name,
                            "Process disappeared while Task Manager was open",
                            AlertSeverity.Medium);
                    }
                }
            }
        }

        public bool IsTaskManagerOpen => _tmWasOpen;
    }
}
