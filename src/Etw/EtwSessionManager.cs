using System;
using System.Threading;
using Wraith.Detection;
using Wraith.Models;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace Wraith.Etw
{
    public class EtwSessionManager : IDisposable
    {
        private TraceEventSession _kernelSession;
        private TraceEventSession _userSession;
        private Thread _kernelThread;
        private Thread _userThread;
        private readonly ProcessTracker _tracker;
        private bool _disposed;

        private static readonly Guid Win32kGuid =
            new Guid("8C416C79-D49B-4F01-A467-E56D3AA8234C");

        private const long Win32kKeywords = 0x2000 | 0x400;

        public Action<EtwEventLog> OnEvent { get; set; }
        public Action<string> OnError { get; set; }
        public Action<string> OnStatus { get; set; }

        public EtwSessionManager(ProcessTracker tracker)
        {
            _tracker = tracker;
        }

        public bool Start()
        {
            bool kernelOk = StartKernelSession();
            bool userOk = StartUserSession();
            return kernelOk || userOk;
        }

        private bool StartKernelSession()
        {
            try
            {
                _kernelSession = new TraceEventSession(KernelTraceEventParser.KernelSessionName);
                _kernelSession.EnableKernelProvider(
                    KernelTraceEventParser.Keywords.Process |
                    KernelTraceEventParser.Keywords.Thread |
                    KernelTraceEventParser.Keywords.FileIO);

                _kernelSession.Source.Kernel.ProcessStart += OnProcessStart;
                _kernelSession.Source.Kernel.ProcessStop += OnProcessStop;
                _kernelSession.Source.Kernel.ThreadStart += OnThreadStart;

                _kernelSession.Source.Kernel.FileIOFileCreate += OnFileCreate;

                try
                {
                    _kernelSession.Source.Kernel.FileIOWrite += OnFileIOWrite;
                }
                catch { }

                try
                {
                    _kernelSession.Source.Kernel.FileIOClose += OnFileClose;
                }
                catch { }

                _kernelThread = new Thread(() =>
                {
                    try { _kernelSession.Source.Process(); }
                    catch (Exception ex) { OnError?.Invoke($"Kernel source stopped: {ex.Message}"); }
                })
                { IsBackground = true, Name = "ETW-Kernel" };
                _kernelThread.Start();

                OnStatus?.Invoke("Kernel session started (Process, Thread, FileIO)");
                return true;
            }
            catch (Exception ex)
            {
                OnError?.Invoke($"Kernel session failed: {ex.Message}");
                OnError?.Invoke("NT Kernel Logger may be in use by another tool (e.g. Process Monitor).");
                return false;
            }
        }

        private bool StartUserSession()
        {
            try
            {
                _userSession = new TraceEventSession("EtwMonitorUser");
                _userSession.EnableProvider(Win32kGuid, TraceEventLevel.Verbose, (ulong)Win32kKeywords);

                _userSession.Source.AllEvents += OnWin32kEvent;

                _userThread = new Thread(() =>
                {
                    try { _userSession.Source.Process(); }
                    catch (Exception ex) { OnError?.Invoke($"User session source stopped: {ex.Message}"); }
                })
                { IsBackground = true, Name = "ETW-User" };
                _userThread.Start();

                OnStatus?.Invoke("User session started (Win32k: Focus + AuditApiCalls)");
                return true;
            }
            catch (Exception ex)
            {
                OnError?.Invoke($"User session failed: {ex.Message}");
                return false;
            }
        }

        private void OnProcessStart(ProcessTraceData data)
        {
            _tracker.GetOrCreate(data.ProcessID, data.ProcessName, data.ImageFileName);
            EmitEvent(EtwEventType.ProcessStart, data.ProcessID, data.ProcessName,
                $"Path={data.ImageFileName}");
        }

        private void OnProcessStop(ProcessTraceData data)
        {
            _tracker.RemoveProcess(data.ProcessID);
            EmitEvent(EtwEventType.ProcessStop, data.ProcessID, data.ProcessName,
                "Process exited");
        }

        private void OnThreadStart(ThreadTraceData data)
        {
            _tracker.RecordThreadStart(data.ProcessID);
            EmitEvent(EtwEventType.ThreadStart, data.ProcessID, data.ProcessName,
                $"TID={data.ThreadID} StartAddr=0x{data.StartAddr:X}");
        }

        private void OnFileCreate(FileIONameTraceData data)
        {
            _tracker.RecordFileOpen(data.ProcessID, data.FileName, data.FileKey);
            EmitEvent(EtwEventType.FileOpen, data.ProcessID, data.ProcessName, data.FileName);
        }

        private void OnFileIOWrite(FileIOReadWriteTraceData data)
        {
            _tracker.RecordFileWrite(data.ProcessID, data.FileKey, data.FileName);
            EmitEvent(EtwEventType.FileWrite, data.ProcessID, data.ProcessName,
                $"Offset={data.Offset} Size={data.IoSize}");
        }

        private void OnFileClose(FileIOSimpleOpTraceData data)
        {
            _tracker.RecordFileClose(data.ProcessID, data.FileKey);
        }

        private void OnWin32kEvent(TraceEvent data)
        {
            if (data.ProviderGuid != Win32kGuid)
                return;

            int pid = data.ProcessID;
            string procName = data.ProcessName;
            string eventName = data.EventName;

            long keywords = (long)data.Keywords;

            if ((keywords & 0x2000) != 0)
            {
                _tracker.IncrementFocus(pid);
                EmitEvent(EtwEventType.Win32kFocus, pid, procName, eventName);
            }

            if ((keywords & 0x400) != 0)
            {
                _tracker.RecordAuditApiCall(pid);
                EmitEvent(EtwEventType.Win32kApiCall, pid, procName, eventName);
            }
        }

        private void EmitEvent(EtwEventType type, int pid, string procName, string detail)
        {
            OnEvent?.Invoke(new EtwEventLog
            {
                Timestamp = DateTime.Now,
                Type = type,
                PID = pid,
                ProcessName = procName ?? "",
                Detail = detail ?? ""
            });
        }

        public void Stop()
        {
            try { _kernelSession?.Stop(); } catch { }
            try { _userSession?.Stop(); } catch { }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            Stop();
            try { _kernelSession?.Dispose(); } catch { }
            try { _userSession?.Dispose(); } catch { }
        }
    }
}
