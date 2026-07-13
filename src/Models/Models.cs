using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace Wraith.Models
{
    public enum AlertSeverity
    {
        Low,
        Medium,
        High
    }

    public enum DetectionType
    {
        ThreadInjection,
        NoWindowFocusApi,
        NoWindowLogWrites,
        PeriodicFileWrites,
        AuditApiCallNoWindow,
        TaskManagerEvasion,
        DllInjection,
        RegistryPersistence,
        ClipboardAccess,
        NamedPipe
    }

    public enum EtwEventType
    {
        ProcessStart,
        ProcessStop,
        ThreadStart,
        ThreadStop,
        FileOpen,
        FileWrite,
        FileClose,
        Win32kFocus,
        Win32kApiCall,
        ImageLoad,
        ImageUnload,
        RegistryWrite,
        ClipboardRead,
        ClipboardWrite,
        NamedPipeCreate,
        NamedPipeConnect,
        TmEvasion
    }

    public class ProcessInfo
    {
        public int PID;
        public string Name = "";
        public string Path = "";
        public DateTime FirstSeen;
        public DateTime LastSeen;
        public bool HasVisibleWindow;
        public string WindowTitle = "";
        public int FocusEventCount;
        public int FileWriteCount;
        public int LogFileWriteCount;
        public int FileOpenCount;
        public int ThreadCreateCount;
        public int AuditApiCallCount;
        public int DllLoadCount;
        public int SuspiciousDllLoadCount;
        public int RegistryWriteCount;
        public int ClipboardReadCount;
        public int ClipboardWriteCount;
        public int NamedPipeCount;
        public HashSet<string> LogFilesOpened = new HashSet<string>();
        public List<DateTime> LogFileWriteTimestamps = new List<DateTime>();
        public Dictionary<ulong, string> FileObjectMap = new Dictionary<ulong, string>();
        public List<DllLoadRecord> DllLoads = new List<DllLoadRecord>();
        public List<RegistryWriteRecord> RegistryWrites = new List<RegistryWriteRecord>();
        public List<string> NamedPipes = new List<string>();
        public bool AlertedNoWindowFocus;
        public bool AlertedNoWindowLogWrites;
        public bool AlertedPeriodicWrites;
        public bool AlertedAuditApiCall;
        public bool AlertedThreadInjection;
        public bool AlertedDllInjection;
        public bool AlertedRegistryPersistence;
        public bool AlertedClipboardAccess;
        public bool AlertedNamedPipe;
    }

    public class DllLoadRecord
    {
        public DateTime Timestamp;
        public string DllPath = "";
        public bool IsSuspicious;
        public string Reason = "";
    }

    public class RegistryWriteRecord
    {
        public DateTime Timestamp;
        public string KeyPath = "";
        public string ValueName = "";
        public bool IsPersistenceKey;
    }

    public class AlertEvent
    {
        public DateTime Timestamp;
        public int PID;
        public string ProcessName = "";
        public AlertSeverity Severity;
        public DetectionType Type;
        public string Message = "";
    }

    public class EtwEventLog
    {
        public DateTime Timestamp;
        public EtwEventType Type;
        public int PID;
        public string ProcessName = "";
        public string Detail = "";
    }

    public class ProcessSnapshot
    {
        public int PID;
        public string Name = "";
        public string Path = "";
        public long WorkingSet64;
        public TimeSpan TotalProcessorTime;
    }

    public class EventLogViewModel : INotifyPropertyChanged
    {
        private string _timeStr;
        private string _typeTag;
        private string _pidStr;
        private string _name;
        private string _detail;
        private string _color;

        public string TimeStr { get => _timeStr; set { _timeStr = value; OnPropertyChanged(); } }
        public string TypeTag { get => _typeTag; set { _typeTag = value; OnPropertyChanged(); } }
        public string PidStr { get => _pidStr; set { _pidStr = value; OnPropertyChanged(); } }
        public string Name { get => _name; set { _name = value; OnPropertyChanged(); } }
        public string Detail { get => _detail; set { _detail = value; OnPropertyChanged(); } }
        public string Color { get => _color; set { _color = value; OnPropertyChanged(); } }

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string n = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));
    }

    public class ProcessViewModel : INotifyPropertyChanged
    {
        private int _pid;
        private string _name = "";
        private string _path = "";
        private double _memMB;
        private bool _hasWindow;
        private bool _isSuspicious;
        private string _reason = "";
        private string _severityColor = "#8b949e";
        private DateTime _firstDetected;
        private int _dllLoads;
        private int _registryWrites;
        private int _clipboardAccess;
        private int _pipeCount;
        private int _focusEvents;
        private int _fileWrites;
        private int _threadCount;
        private int _apiCalls;

        public int PID { get => _pid; set { _pid = value; OnPropertyChanged(); } }
        public string Name { get => _name; set { _name = value; OnPropertyChanged(); } }
        public string Path { get => _path; set { _path = value; OnPropertyChanged(); } }
        public double MemMB { get => _memMB; set { _memMB = value; OnPropertyChanged(); } }
        public bool HasWindow { get => _hasWindow; set { _hasWindow = value; OnPropertyChanged(); } }
        public bool IsSuspicious { get => _isSuspicious; set { _isSuspicious = value; OnPropertyChanged(); } }
        public string Reason { get => _reason; set { _reason = value; OnPropertyChanged(); } }
        public string SeverityColor { get => _severityColor; set { _severityColor = value; OnPropertyChanged(); } }
        public DateTime FirstDetected { get => _firstDetected; set { _firstDetected = value; OnPropertyChanged(); } }
        public int DllLoads { get => _dllLoads; set { _dllLoads = value; OnPropertyChanged(); } }
        public int RegistryWrites { get => _registryWrites; set { _registryWrites = value; OnPropertyChanged(); } }
        public int ClipboardAccess { get => _clipboardAccess; set { _clipboardAccess = value; OnPropertyChanged(); } }
        public int PipeCount { get => _pipeCount; set { _pipeCount = value; OnPropertyChanged(); } }
        public int FocusEvents { get => _focusEvents; set { _focusEvents = value; OnPropertyChanged(); } }
        public int FileWrites { get => _fileWrites; set { _fileWrites = value; OnPropertyChanged(); } }
        public int ThreadCount { get => _threadCount; set { _threadCount = value; OnPropertyChanged(); } }
        public int ApiCalls { get => _apiCalls; set { _apiCalls = value; OnPropertyChanged(); } }

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string n = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));
    }

    public class AlertViewModel : INotifyPropertyChanged
    {
        private string _timeStr;
        private string _severityText;
        private string _severityColor;
        private int _pid;
        private string _processName = "";
        private string _message = "";
        private bool _isActive = true;
        private DetectionType _type;

        public string TimeStr { get => _timeStr; set { _timeStr = value; OnPropertyChanged(); } }
        public string SeverityText { get => _severityText; set { _severityText = value; OnPropertyChanged(); } }
        public string SeverityColor { get => _severityColor; set { _severityColor = value; OnPropertyChanged(); } }
        public int PID { get => _pid; set { _pid = value; OnPropertyChanged(); } }
        public string ProcessName { get => _processName; set { _processName = value; OnPropertyChanged(); } }
        public string Message { get => _message; set { _message = value; OnPropertyChanged(); } }
        public bool IsActive { get => _isActive; set { _isActive = value; OnPropertyChanged(); } }
        public DetectionType Type { get => _type; set { _type = value; OnPropertyChanged(); } }

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string n = null) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));
    }
}
