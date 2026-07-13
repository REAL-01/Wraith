using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Wraith.Detection
{
    public class WindowScanner
    {
        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowTextW(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowTextLengthW(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        public Dictionary<int, (bool hasWindow, string title)> Scan()
        {
            var result = new Dictionary<int, (bool, string)>();

            EnumWindows((hWnd, lParam) =>
            {
                if (!IsWindowVisible(hWnd))
                    return true;

                int length = GetWindowTextLengthW(hWnd);
                if (length == 0)
                    return true;

                var sb = new StringBuilder(length + 1);
                GetWindowTextW(hWnd, sb, sb.Capacity);

                GetWindowThreadProcessId(hWnd, out uint pid);
                int pidInt = (int)pid;

                if (!result.ContainsKey(pidInt))
                {
                    result[pidInt] = (true, sb.ToString());
                }

                return true;
            }, IntPtr.Zero);

            return result;
        }
    }
}
