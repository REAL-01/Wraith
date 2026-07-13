using System;
using System.Collections.Generic;
using System.Linq;

namespace Wraith.Detection
{
    public static class SystemProcessFilter
    {
        private static readonly HashSet<string> SystemProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "system", "system idle process", "registry", "idle",
            "smss", "csrss", "wininit", "winlogon", "services", "lsass", "svchost",
            "dwm", "fontdrvhost", "dllhost", "runtimebroker", "sihost", "taskhostw",
            "conhost", "searchindexer", "searchhost", "startmenuexperiencehost",
            "shellexperiencehost", "textinputhost", "ctfmon", "backgroundtaskhost",
            "applicationframehost", "useroobebroker", "explorer", "spoolsv",
            "dashost", "wudfhost", "msmpeng", "nissrv", "securityhealthservice",
            "securityhealthsystray", "mpcmdrun", "widgetservice", "phoneexperiencehost",
            "systemsettings", "mumshelper", "edgetarget", "browser",
            "microsoftedgeupdate", "officeclicktorun", "bthavctpsvc",
            "windowsinternal.composableshell.experiences.textinput.inputapp",
            "windows.internal.ui.composition.windowhost",
            "video processexim", "video.processexim", "systeminformaticshelper",
            "searchprotocolhost", "searchfilterhost", "trustedinstaller",
            "tiworker", "wuauclt", "musnotification", "musnotifyuser",
            "backgroundtransferhost", "backgroundtaskhost",
            "devicecensususermode", "dmcfghost", "dmclient",
            "wermgr", "werfault", "werfaultsecure",
            "audiodg", "rundll32", "regsvr32", "msiexec",
            "schtasks", "taskeng", "taskhost",
            "wbemtest", "wmiprvse", "unregmp2", "mobsync",
            "snmptrap", "tapiui", "ndiskapi", "ndiscap",
            "rdpclip", "rdpinput", "mstsc", "rdpclient",
            "wifitray", "wifinetworkmanager", "wlanext",
            "wpbbin", "wpbcom", "wpbnsrv",
            "aclayerui", "acgenral", "acredir", "acwow",
            "arp", "atbroker", "autologon", "autounattend",
            "bcdedit", "bitsadmin", "cacls", "certutil",
            "chkdsk", "choice", "cipher", "cleanmgr",
            "clip", "cmd", "cscript", "defrag",
            "diskpart", "diskperf", "doskey", "dps",
            "driverquery", "eventcreate", "eventvwr",
            "expand", "extrac32", "fciv", "findstr",
            "finger", "flattemp", "fltmc", "forfiles",
            "format", "freecell", "fsutil", "ftp",
            "getmac", "gpresult", "gpupdate", "hostname",
            "icacls", "iexpress", "irftp", "kbdedit",
            "klist", "ksetup", "label", "lodctr",
            "logman", "logoff", "lpq", "lpr",
            "makecab", "mbsacli", "mem", "mkdir",
            "mmc", "mode", "more", "mountvol",
            "move", "mqbkup", "mqtgsvc", "mrinfo",
            "msg", "msdt", "msra", "nbtstat",
            "net", "netcfg", "netsh", "netstat",
            "nltest", "notepad", "nslookup", "ntbackup",
            "ntfrsutl", "openfiles", "pagefileconfig",
            "pathping", "perfmon", "ping", "plugplay",
            "pnputil", "populated places", "powercfg",
            "powershell", "pwsh", "print", "prndrv",
            "prnmngr", "prnport", "prnqctl", "pro quotas",
            "proxycfg", "qappsrv", "qprocess", "qwinsta",
            "rasdial", "raserver", "rcp", "rdpsign",
            "recover", "redir", "reg", "regini",
            "replace", "reset", "rexec", "route",
            "rpcping", "rsh", "runas", "rundll",
            "sc", "schtasks", "sclnt", "scrnsave",
            "set", "setlocal", "setx", "sfc",
            "shadow", "share", "shutdown", "sort",
            "start", "subst", "sxstrace", "sysocmgr",
            "systeminfo", "takeown", "tapicfg", "taskkill",
            "tasklist", "tcmsetup", "telnet", "tftp",
            "tlntadmn", "tlntsess", "tlntsvr", "tpmvscmgr",
            "tracerpt", "tracert", "tscon", "tsdiscon",
            "tsecimp", "tskill", "tsprof", "type",
            "unlodctr", "verifier", "ver", "vssadmin",
            "w32tm", "waitfor", "wbadmin", "wecutil",
            "where", "whoami", "winmsd", "winrs",
            "winrm", "winsat", "wmic", "wscript",
            "wsman", "wsmprovhost", "xcopy",
            "appidsvc", "appidservice", "certenrollctrl",
            "dcomlaunch", "devicecensus", "devicesflowusermode",
            "deviceservicemanager", "dism", "dismhost",
            "dnsbroker", "edgeinstaller", "fileexplorer",
            "gamingservices", "inputapp", "lockapp",
            "logonui", "metricsgrader", "narrator",
            "ndiskapi", "nvidia", "nvcontainer",
            "nvsrvctl", "officebackgroundtaskhandler",
            "oygeninputhost", "printisolationhost",
            "processrmdhost", "prognosis", "runonce",
            "searchindexer", "sgrmbroker", "signalsys",
            "slui", "spectrumnext", "spoolsv",
            "system informatics", "tabcal", "tabtip",
            "tabtip32", "textinputhost", "tpkbmsvc",
            "tscupdatetool", "tswbprxy", "uwpkylin",
            "uwpkylinuia", "vds", "volmgrx",
            "vssvc", "wab32res", "windowsterminal",
            "winver", "wisptis", "wksprv",
            "wlidsvc", "wlidsvcm", "wlpasvc",
            "wmiadapt", "wmiprvse", "wmpnetwk",
            "wpnpinst", "wudfhost", "wwahost",
            "nvspctrl", "nvbackend", "nvcplui",
            "nvcpl", "nvsmartmax", "nvsmsngr",
            "nvidia tegra","nvidia container","nvdisplay.container",
            "nvidia.backend","nvidia.overlay","nvcontainer",
            "rthdvcpl", "rthdcpl", "rtserv", "rtkaudio",
            "realsched", "realtek", "rundll32",
            "igfxtray", "igfxsrvc", "igfxpers",
            "igfxext", "igfxcfg", "igfxdo",
            "hkcmd", "igfxhm", "igfxmtc",
            "btplayerctrl", "btdrt", "bthudtask",
            "oobesetup", "oobemcreg", "musnotifyicon",
            "notificationutilshost", "notificationmanagerhost",
            "pushnotificationsvc", "pushnotificationservice",
            "windowsactiondialog", "windowsdefaultbeep",
            "windowsfirewall", "windowsupdateclient",
            "windowsdefender", "windowssecurity",
            "ntoskrnl", "hal", "acpi",
            "ndis", "tcpip", "http",
            "afd", "ndisuio", "ndiswan",
            "raspptp", "rasl2tp", "raspppoe",
            "ndisip", "ipfltdrv", "msgpc",
            "rdbss", "rxfilter", "rxfilterdriver",
            "luafv", "bindflt", "wcifs",
            "tunnelproxyhost", "tunnelproxyservice",
            "msteamsupdate", "teams", "msedge",
            "chrome", "firefox", "opera",
            "code", "devenv", "ssms",
            "git", "node", "python",
            "dotnet", "msbuild", "nuget"
        };

        private static readonly HashSet<string> SystemPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            @"c:\windows\system32\",
            @"c:\windows\syswow64\",
            @"c:\windows\winsxs\",
            @"c:\windows\servicing\",
            @"c:\windows\assembly\",
            @"c:\windows\microsoft.net\",
            @"c:\windows\diagnostics\",
            @"c:\windows\explorer\",
            @"c:\program files\windowsapps\",
            @"c:\program files\windows defender\",
            @"c:\program files (x86)\windows defender\",
            @"c:\program files\microsoft\",
            @"c:\program files (x86)\microsoft\",
            @"c:\program files\common files\microsoft shared\",
            @"c:\program files (x86)\common files\microsoft shared\",
            @"c:\windows\systemresources\",
            @"c:\windows\shellcomponents\",
            @"c:\windows\immersivecontrolpanel\",
            @"c:\program files\windows media player\",
            @"c:\program files (x86)\microsoft\edge\",
            @"c:\program files\microsoft\edge\",
            @"c:\windows\system32\drivers\",
        };

        public static bool IsSystemProcess(string processName)
        {
            if (string.IsNullOrEmpty(processName))
                return true;

            var name = processName.ToLowerInvariant().Trim();
            if (name.EndsWith(".exe"))
                name = name.Substring(0, name.Length - 4);

            return SystemProcesses.Contains(name);
        }

        public static bool IsSystemProcess(string processName, string processPath)
        {
            if (IsSystemProcess(processName))
                return true;

            if (string.IsNullOrEmpty(processPath))
                return false;

            var lower = processPath.ToLowerInvariant();

            foreach (var sysPath in SystemPaths)
            {
                if (lower.StartsWith(sysPath))
                    return true;
            }

            return false;
        }

        public static bool ShouldIgnore(string processName, string processPath)
        {
            return IsSystemProcess(processName, processPath);
        }
    }
}
