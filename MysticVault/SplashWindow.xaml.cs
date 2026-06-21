using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media.Animation;

namespace MysticVault;

public partial class SplashWindow : Window
{
    public SplashWindow()
    {
        InitializeComponent();
        Loaded += SplashWindow_Loaded;
    }

    private async void SplashWindow_Loaded(object sender, RoutedEventArgs e)
    {
        var fadeIn = (Storyboard)Resources["FadeIn"];
        Storyboard.SetTarget(fadeIn, MainBorder);
        fadeIn.Begin();

        await Task.Delay(1500);

        var fadeOut = (Storyboard)Resources["FadeOut"];
        Storyboard.SetTarget(fadeOut, MainBorder);
        
        fadeOut.Completed += (s, ev) =>
        {
            var mainWindow = new MainWindow();
            mainWindow.Show();
            Close();
        };
        
        fadeOut.Begin();
    }
}
