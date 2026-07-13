using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using Wraith.Models;

namespace Wraith.Detection
{
    public class ProcessTracker
    {
        private readonly ConcurrentDictionary<int, ProcessInfo> _processes = new ConcurrentDictionary<int, ProcessInfo>();
        private readonly object _updateLock = new object();

        public ProcessInfo GetOrCreate(int pid, string name = null, string path = null)
        {
            return _processes.GetOrAdd(pid, key =>
            {
                var info = new ProcessInfo
                {
                    PID = key,
                    Name = name ?? $"PID_{key}",
                    Path = path ?? "",
                    FirstSeen = DateTime.Now,
                    LastSeen = DateTime.Now
                };
                return info;
            });
        }

        public ProcessInfo GetProcess(int pid)
        {
            _processes.TryGetValue(pid, out var proc);
            return proc;
        }

        public void UpdateWindowInfo(Dictionary<int, (bool, string)> windowMap)
        {
            foreach (var kvp in _processes)
            {
                if (windowMap.TryGetValue(kvp.Key, out var info))
                {
                    kvp.Value.HasVisibleWindow = info.Item1;
                    kvp.Value.WindowTitle = info.Item2;
                }
                else
                {
                    kvp.Value.HasVisibleWindow = false;
                    kvp.Value.WindowTitle = "";
                }
            }
        }

        public void IncrementFocus(int pid)
        {
            var proc = GetOrCreate(pid);
            lock (_updateLock)
            {
                proc.FocusEventCount++;
                proc.LastSeen = DateTime.Now;
            }
        }

        public void RecordFileOpen(int pid, string fileName, ulong fileKey)
        {
            var proc = GetOrCreate(pid);
            lock (_updateLock)
            {
                proc.FileOpenCount++;
                proc.LastSeen = DateTime.Now;
                if (proc.FileObjectMap.Count < 4096)
                {
                    proc.FileObjectMap[fileKey] = fileName;
                }
                var lower = fileName.ToLowerInvariant();
                if (lower.EndsWith(".txt") || lower.EndsWith(".log") ||
                    lower.EndsWith(".csv") || lower.EndsWith(".dat"))
                {
                    proc.LogFilesOpened.Add(fileName);
                }
            }
        }

        public void RecordFileWrite(int pid, ulong fileKey, string fileName)
        {
            var proc = GetOrCreate(pid);
            lock (_updateLock)
            {
                proc.FileWriteCount++;
                proc.LastSeen = DateTime.Now;

                string actualName = fileName;
                if (string.IsNullOrEmpty(actualName) &&
                    proc.FileObjectMap.TryGetValue(fileKey, out var mapped))
                {
                    actualName = mapped;
                }

                if (!string.IsNullOrEmpty(actualName))
                {
                    var lower = actualName.ToLowerInvariant();
                    if (lower.EndsWith(".txt") || lower.EndsWith(".log") || lower.EndsWith(".csv"))
                    {
                        proc.LogFileWriteCount++;
                        proc.LogFileWriteTimestamps.Add(DateTime.Now);
                        if (proc.LogFileWriteTimestamps.Count > 50)
                        {
                            proc.LogFileWriteTimestamps.RemoveAt(0);
                        }
                    }
                }
            }
        }

        public void RecordFileClose(int pid, ulong fileKey)
        {
            var proc = GetProcess(pid);
            if (proc == null) return;
            lock (_updateLock)
            {
                proc.FileObjectMap.Remove(fileKey);
            }
        }

        public void RecordThreadStart(int pid)
        {
            var proc = GetOrCreate(pid);
            lock (_updateLock)
            {
                proc.ThreadCreateCount++;
                proc.LastSeen = DateTime.Now;
            }
        }

        public void RecordAuditApiCall(int pid)
        {
            var proc = GetOrCreate(pid);
            lock (_updateLock)
            {
                proc.AuditApiCallCount++;
                proc.LastSeen = DateTime.Now;
            }
        }

        public void RemoveProcess(int pid)
        {
            _processes.TryRemove(pid, out _);
        }

        public List<ProcessInfo> GetAllProcesses()
        {
            return new List<ProcessInfo>(_processes.Values);
        }

        public int Count => _processes.Count;
    }
}
