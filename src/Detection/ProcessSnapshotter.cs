using System;
using System.Collections.Generic;
using System.Diagnostics;
using Wraith.Models;

namespace Wraith.Detection
{
    public class ProcessSnapshotter
    {
        public List<ProcessSnapshot> Snapshot()
        {
            var result = new List<ProcessSnapshot>();
            var procs = Process.GetProcesses();
            foreach (var p in procs)
            {
                try
                {
                    var snap = new ProcessSnapshot
                    {
                        PID = p.Id,
                        Name = p.ProcessName
                    };
                    try { snap.WorkingSet64 = p.WorkingSet64; } catch { }
                    try { snap.TotalProcessorTime = p.TotalProcessorTime; } catch { }
                    try { snap.Path = p.MainModule?.FileName ?? ""; } catch { }
                    result.Add(snap);
                }
                catch { }
                finally
                {
                    try { p.Dispose(); } catch { }
                }
            }
            return result;
        }

        public ProcessSnapshot GetProcess(int pid)
        {
            try
            {
                var p = Process.GetProcessById(pid);
                var snap = new ProcessSnapshot
                {
                    PID = p.Id,
                    Name = p.ProcessName
                };
                try { snap.WorkingSet64 = p.WorkingSet64; } catch { }
                try { snap.TotalProcessorTime = p.TotalProcessorTime; } catch { }
                try { snap.Path = p.MainModule?.FileName ?? ""; } catch { }
                p.Dispose();
                return snap;
            }
            catch
            {
                return null;
            }
        }

        public bool IsProcessRunning(int pid)
        {
            try
            {
                var p = Process.GetProcessById(pid);
                p.Dispose();
                return true;
            }
            catch { return false; }
        }

        public bool KillProcess(int pid)
        {
            try
            {
                var p = Process.GetProcessById(pid);
                p.Kill(entireProcessTree: true);
                p.WaitForExit(5000);
                p.Dispose();
                return true;
            }
            catch { return false; }
        }
    }
}
