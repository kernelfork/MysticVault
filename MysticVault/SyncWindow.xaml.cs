using System;
using System.IO;
using System.Windows;
using System.Windows.Media.Imaging;
using QRCoder;

namespace MysticVault;

public partial class SyncWindow : Window
{
    private readonly SyncManager _syncManager;

    public SyncWindow(VaultManager vault)
    {
        InitializeComponent();
        _syncManager = new SyncManager(vault);
        
        Loaded += OnLoaded;
        Closing += OnClosing;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        try
        {
            string url = _syncManager.StartServer();
            GenerateQrCode(url);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to start local sync server. Ensure your firewall allows inbound connections on port 5555.\n\nError: {ex.Message}", "Sync Error", MessageBoxButton.OK, MessageBoxImage.Error);
            Close();
        }
    }

    private void GenerateQrCode(string url)
    {
        using var qrGenerator = new QRCodeGenerator();
        using var qrCodeData = qrGenerator.CreateQrCode(url, QRCodeGenerator.ECCLevel.Q);
        using var qrCode = new PngByteQRCode(qrCodeData);
        byte[] qrCodeImage = qrCode.GetGraphic(20);
        
        using var ms = new MemoryStream(qrCodeImage);
        var bitmapImage = new BitmapImage();
        bitmapImage.BeginInit();
        bitmapImage.CacheOption = BitmapCacheOption.OnLoad;
        bitmapImage.StreamSource = ms;
        bitmapImage.EndInit();
        
        QrImage.Source = bitmapImage;
    }

    private void OnClosing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        _syncManager.StopServer();
    }
}
