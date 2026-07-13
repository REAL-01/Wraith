using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text.Json;
using System.Threading.Tasks;

namespace Wraith.Core
{
    public class UpdateChecker
    {
        private const string ApiUrl = "https://api.github.com/repos/REAL-01/Wraith/releases/latest";
        private const string CurrentVersion = "2.1.1";

        public string LatestVersion { get; private set; }
        public string DownloadUrl { get; private set; }
        public bool IsLatest { get; private set; } = true;

        public async Task CheckAsync()
        {
            try
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;

                using var client = new HttpClient();
                client.DefaultRequestHeaders.Add("User-Agent", "Wraith/2.1.1");
                client.Timeout = TimeSpan.FromSeconds(10);

                var json = await client.GetStringAsync(ApiUrl);
                using var doc = JsonDocument.Parse(json);

                LatestVersion = doc.RootElement.GetProperty("tag_name").GetString();

                if (LatestVersion.StartsWith("v"))
                    LatestVersion = LatestVersion.Substring(1);

                IsLatest = VersionEquals(LatestVersion, CurrentVersion);

                if (!IsLatest)
                {
                    foreach (var asset in doc.RootElement.GetProperty("assets").EnumerateArray())
                    {
                        var name = asset.GetProperty("name").GetString();
                        if (name != null && name.Contains("Portable"))
                        {
                            DownloadUrl = asset.GetProperty("browser_download_url").GetString();
                            break;
                        }
                    }

                    if (string.IsNullOrEmpty(DownloadUrl))
                    {
                        foreach (var asset in doc.RootElement.GetProperty("assets").EnumerateArray())
                        {
                            var name = asset.GetProperty("name").GetString();
                            if (name != null && name.EndsWith(".zip"))
                            {
                                DownloadUrl = asset.GetProperty("browser_download_url").GetString();
                                break;
                            }
                        }
                    }
                }
            }
            catch
            {
                IsLatest = true;
                LatestVersion = CurrentVersion;
            }
        }

        public async Task<bool> UpdateAsync(Action<int, string> progress = null)
        {
            if (string.IsNullOrEmpty(DownloadUrl))
                return false;

            try
            {
                var tempDir = Path.Combine(Path.GetTempPath(), "WraithUpdate");
                if (Directory.Exists(tempDir))
                    Directory.Delete(tempDir, true);
                Directory.CreateDirectory(tempDir);

                var zipPath = Path.Combine(tempDir, "update.zip");

                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;
                using var client = new HttpClient();
                client.DefaultRequestHeaders.Add("User-Agent", "Wraith/2.1.1");
                client.Timeout = TimeSpan.FromMinutes(10);

                using var resp = await client.GetAsync(DownloadUrl, HttpCompletionOption.ResponseHeadersRead);
                resp.EnsureSuccessStatusCode();

                var total = resp.Content.Headers.ContentLength ?? -1;
                long downloaded = 0;

                using var src = await resp.Content.ReadAsStreamAsync();
                using var dst = File.Create(zipPath);
                byte[] buf = new byte[81920];
                int n;
                while ((n = await src.ReadAsync(buf, 0, buf.Length)) > 0)
                {
                    dst.Write(buf, 0, n);
                    downloaded += n;
                    if (total > 0)
                        progress?.Invoke((int)((downloaded * 100) / total), $"{downloaded / 1048576.0:F1} MB");
                }

                progress?.Invoke(100, "extracting...");

                ZipFile.ExtractToDirectory(zipPath, tempDir, true);
                File.Delete(zipPath);

                var currentExe = Process.GetCurrentProcess().MainModule.FileName;
                var currentDir = Path.GetDirectoryName(currentExe);
                var updaterPath = Path.Combine(tempDir, "update.bat");
                var backupExe = currentExe + ".bak";

                var bat = $@"@echo off
timeout /t 1 /nobreak >nul
taskkill /f /im Wraith.exe >nul 2>&1
if exist ""{backupExe}"" del ""{backupExe}""
copy ""{currentExe}"" ""{backupExe}""
xcopy /y /e ""{tempDir}\*"" ""{currentDir}\""
del ""{currentExe}.bak""
start """" ""{currentExe}""
rmdir /s /q ""{tempDir}""
";
                File.WriteAllText(updaterPath, bat);

                Process.Start(new ProcessStartInfo
                {
                    FileName = updaterPath,
                    UseShellExecute = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true
                });

                return true;
            }
            catch
            {
                return false;
            }
        }

        private static bool VersionEquals(string a, string b)
        {
            if (string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b))
                return true;

            var pa = a.Split('.');
            var pb = b.Split('.');

            int len = Math.Max(pa.Length, pb.Length);
            for (int i = 0; i < len; i++)
            {
                int va = 0, vb = 0;
                if (i < pa.Length) int.TryParse(pa[i], out va);
                if (i < pb.Length) int.TryParse(pb[i], out vb);
                if (va != vb) return false;
            }
            return true;
        }
    }
}
