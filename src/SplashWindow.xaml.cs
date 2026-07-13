using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media.Animation;
using System.Windows.Threading;

namespace Wraith
{
    public partial class SplashWindow : Window
    {
        private Storyboard _sbIn;
        private Storyboard _sbGlow;
        private Storyboard _sbText;
        private Storyboard _sbScan;
        private Storyboard _sbOut;

        public SplashWindow()
        {
            InitializeComponent();
            Loaded += SplashWindow_Loaded;
        }

        private void SplashWindow_Loaded(object sender, RoutedEventArgs e)
        {
            _sbIn = (Storyboard)Resources["SplashIn"];
            _sbGlow = (Storyboard)Resources["SplashGlow"];
            _sbText = (Storyboard)Resources["TextReveal"];
            _sbScan = (Storyboard)Resources["ScanLine"];
            _sbOut = (Storyboard)Resources["SplashOut"];

            _sbIn.Begin(this);
            _sbGlow.Begin(this);
            _sbText.Begin(this);
            _sbScan.Begin(this);

            var loadAnim = new DoubleAnimation
            {
                From = 0,
                To = 220,
                Duration = TimeSpan.FromMilliseconds(2400),
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut }
            };
            LoadBar.BeginAnimation(WidthProperty, loadAnim);

            DispatcherTimer closeTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(2800)
            };
            closeTimer.Tick += (s, args) =>
            {
                closeTimer.Stop();
                _sbOut.Completed += (s2, a2) =>
                {
                    DialogResult = true;
                    Close();
                };
                _sbOut.Begin(this);
            };
            closeTimer.Start();
        }
    }
}
