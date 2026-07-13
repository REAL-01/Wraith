using System.Windows;

namespace Wraith
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            var splash = new SplashWindow();
            splash.ShowDialog();

            var main = new MainWindow();
            main.Closing += (s, args) => Current.Shutdown();
            main.Show();
        }
    }
}
