using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using Wraith.Models;

namespace Wraith.Detection
{
    public class ProcessTracker
    {
        private readonly ConcurrentDictionary<int, ProcessInfo> _processes = new ConcurrentDictionary<int, ProcessInfo>();
        private readonly object _updateLock = new object();

        private static readonly string[] SuspiciousDllDirs = {
            "\\temp\\", "\\appdata\\", "\\downloads\\", "\\programdata\\",
            "\\users\\public\\", "\\windows\\temp\\"
        };

        private static readonly string[] PersistenceKeys = {
            "software\\microsoft\\windows\\currentversion\\run",
            "software\\microsoft\\windows\\currentversion\\runonce",
            "software\\wow6432node\\microsoft\\windows\\currentversion\\run",
            "software\\microsoft\\windows nt\\currentversion\\image file execution options",
            "software\\microsoft\\windows nt\\currentversion\\silentprocessexit",
            "software\\microsoft\\windows\\currentversion\\explorer\\shellcmdapps",
            "software\\microsoft\\windows\\currentversion\\uninstall",
            "software\\microsoft\\windows\\currentversion\\scheduled tasks"
        };

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

        public (bool suspicious, string reason) RecordDllLoad(int pid, string dllPath)
        {
            var proc = GetOrCreate(pid);
            bool suspicious = false;
            string reason = "";

            lock (_updateLock)
            {
                proc.DllLoadCount++;
                proc.LastSeen = DateTime.Now;

                var lower = dllPath.ToLowerInvariant();

                foreach (var dir in SuspiciousDllDirs)
                {
                    if (lower.Contains(dir))
                    {
                        suspicious = true;
                        reason = $"DLL loaded from {dir.Trim('\\')}: {Path.GetFileName(dllPath)}";
                        proc.SuspiciousDllLoadCount++;
                        break;
                    }
                }

                var rec = new DllLoadRecord
                {
                    Timestamp = DateTime.Now,
                    DllPath = dllPath,
                    IsSuspicious = suspicious,
                    Reason = reason
                };
                proc.DllLoads.Add(rec);
                if (proc.DllLoads.Count > 200)
                    proc.DllLoads.RemoveAt(0);
            }

            return (suspicious, reason);
        }

        public (bool persistence, string keyPath) RecordRegistryWrite(int pid, string keyPath, string valueName)
        {
            var proc = GetOrCreate(pid);
            bool isPersistence = false;
            string matchedKey = "";

            lock (_updateLock)
            {
                proc.RegistryWriteCount++;
                proc.LastSeen = DateTime.Now;

                var lower = keyPath.ToLowerInvariant();
                foreach (var pk in PersistenceKeys)
                {
                    if (lower.Contains(pk))
                    {
                        isPersistence = true;
                        matchedKey = pk;
                        break;
                    }
                }

                var rec = new RegistryWriteRecord
                {
                    Timestamp = DateTime.Now,
                    KeyPath = keyPath,
                    ValueName = valueName ?? "",
                    IsPersistenceKey = isPersistence
                };
                proc.RegistryWrites.Add(rec);
                if (proc.RegistryWrites.Count > 100)
                    proc.RegistryWrites.RemoveAt(0);
            }

            return (isPersistence, matchedKey);
        }

        public void RecordClipboardRead(int pid)
        {
            var proc = GetOrCreate(pid);
            lock (_updateLock)
            {
                proc.ClipboardReadCount++;
                proc.LastSeen = DateTime.Now;
            }
        }

        public void RecordClipboardWrite(int pid)
        {
            var proc = GetOrCreate(pid);
            lock (_updateLock)
            {
                proc.ClipboardWriteCount++;
                proc.LastSeen = DateTime.Now;
            }
        }

        public void RecordNamedPipe(int pid, string pipeName)
        {
            var proc = GetOrCreate(pid);
            lock (_updateLock)
            {
                proc.NamedPipeCount++;
                proc.LastSeen = DateTime.Now;
                if (proc.NamedPipes.Count < 50)
                    proc.NamedPipes.Add(pipeName);
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
