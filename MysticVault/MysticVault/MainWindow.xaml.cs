using Microsoft.Win32;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
namespace MysticVault;
public partial class MainWindow : Window
{
    private readonly VaultManager _vault = new();
    private static readonly TimeSpan ClipboardClearDelay = TimeSpan.FromSeconds(30);
    private DispatcherTimer? _clipboardClearTimer;
    private DispatcherTimer? _idleTimer;
    private string? _loadedSite;
    private bool _passwordRevealed;
    private bool _suppressPasswordSync;
    private int _generatorLength = 20;
    private bool _useUppercase = true;
    private bool _useLowercase = true;
    private bool _useDigits = true;
    private bool _useSymbols = true;
    private string _generatedPassword = "";
    private static readonly Color[] AvatarPalette =
    {
        Color.FromRgb(0xE9, 0x1E, 0x63), 
        Color.FromRgb(0x9C, 0x27, 0xB0), 
        Color.FromRgb(0x67, 0x3A, 0xB7), 
        Color.FromRgb(0x3F, 0x51, 0xB5), 
        Color.FromRgb(0x21, 0x96, 0xF3), 
        Color.FromRgb(0x00, 0xBC, 0xD4), 
        Color.FromRgb(0x00, 0x96, 0x88), 
        Color.FromRgb(0xFF, 0x57, 0x22), 
    };
    private class SiteDisplayItem
    {
        public string SiteName { get; init; } = "";
        public string Username { get; init; } = "";
        public string AvatarLetter { get; init; } = "";
        public SolidColorBrush AvatarBrush { get; init; } = Brushes.Gray;
    }
    public record ExportEntry(string SiteName, string Username, string Password, string Website);
    public MainWindow()
    {
        InitializeComponent();
        UpdateLockScreenForVaultState();
        Closing += (_, _) => _vault.Lock();
        _idleTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        _idleTimer.Tick += (s, e) =>
        {
            if (_vault.IsUnlocked && GetIdleTimeMs() > 5 * 60 * 1000)
            {
                LockVault();
            }
        };
        _idleTimer.Start();
    }
    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool SetWindowDisplayAffinity(IntPtr hWnd, uint dwAffinity);
    private const uint WDA_EXCLUDEFROMCAPTURE = 0x11;
    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct LASTINPUTINFO
    {
        public uint cbSize;
        public uint dwTime;
    }
    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);
    private static uint GetIdleTimeMs()
    {
        LASTINPUTINFO lastInPut = new LASTINPUTINFO();
        lastInPut.cbSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf(lastInPut);
        if (GetLastInputInfo(ref lastInPut))
        {
            return (uint)Environment.TickCount - lastInPut.dwTime;
        }
        return 0;
    }
    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        var hwnd = new System.Windows.Interop.WindowInteropHelper(this).Handle;
        SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE);
    }
    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2)
            WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        else
            DragMove();
    }
    private void MinimizeButton_Click(object sender, RoutedEventArgs e)
        => WindowState = WindowState.Minimized;
    private void CloseButton_Click(object sender, RoutedEventArgs e)
        => Close();
    private static SolidColorBrush GetAvatarBrush(string siteName)
    {
        int hash = 0;
        foreach (char c in siteName)
            hash = hash * 31 + c;
        return new SolidColorBrush(AvatarPalette[Math.Abs(hash) % AvatarPalette.Length]);
    }
    private static string GetAvatarLetter(string siteName)
        => siteName.Length > 0 ? siteName[0].ToString().ToUpper() : "?";
    private void UpdateLockScreenForVaultState()
    {
        bool vaultExists = VaultManager.VaultExists();
        LockTitleText.Text = vaultExists ? "Unlock MysticVault" : "Create your master password";
        UnlockButton.Content = vaultExists ? "Unlock" : "Create Vault";
        ConfirmLabel.Visibility = vaultExists ? Visibility.Collapsed : Visibility.Visible;
        ConfirmPasswordBox.Visibility = vaultExists ? Visibility.Collapsed : Visibility.Visible;
    }
    private void UnlockButton_Click(object sender, RoutedEventArgs e)
    {
        StatusText.Text = "";
        string password = MasterPasswordBox.Password;
        if (string.IsNullOrEmpty(password))
        {
            StatusText.Text = "Enter a master password.";
            return;
        }
        if (VaultManager.VaultExists())
        {
            var result = _vault.Unlock(password);
            if (result != UnlockResult.Success)
            {
                StatusText.Text = result switch
                {
                    UnlockResult.IncorrectPassword => "Incorrect master password.",
                    UnlockResult.WrongMachineOrAccount =>
                        "This vault was created on a different Windows account or machine, and can't be unlocked here.",
                    UnlockResult.CorruptFile => "The vault file appears to be corrupted or tampered with.",
                    _ => "Unable to unlock."
                };
                MasterPasswordBox.Clear();
                return;
            }
        }
        else
        {
            if (password != ConfirmPasswordBox.Password)
            {
                StatusText.Text = "Passwords didn't match.";
                return;
            }
            _vault.CreateVault(password);
        }
        MasterPasswordBox.Clear();
        ConfirmPasswordBox.Clear();
        ShowVaultPanel();
    }
    private void ShowVaultPanel()
    {
        LockPanel.Visibility = Visibility.Collapsed;
        VaultPanel.Visibility = Visibility.Visible;
        SearchBox.Clear();
        RefreshSitesList();
        ClearDetailFields();
        ShowNoSelectionHint();
    }
    private void RefreshSitesList()
    {
        string? previouslySelected = (SitesListBox.SelectedItem as SiteDisplayItem)?.SiteName;
        var allSites = _vault.Entries.Keys.OrderBy(s => s).ToList();
        string query = SearchBox.Text.Trim();
        var visibleSites = string.IsNullOrEmpty(query)
            ? allSites
            : allSites.Where(s => s.Contains(query, StringComparison.OrdinalIgnoreCase)).ToList();
        var displayItems = visibleSites.Select(s =>
        {
            _vault.Entries.TryGetValue(s, out var entry);
            return new SiteDisplayItem
            {
                SiteName = s,
                Username = entry?.Username ?? "",
                AvatarLetter = GetAvatarLetter(s),
                AvatarBrush = GetAvatarBrush(s)
            };
        }).ToList();
        SitesListBox.ItemsSource = null;
        SitesListBox.ItemsSource = displayItems;
        if (previouslySelected != null)
        {
            for (int i = 0; i < displayItems.Count; i++)
            {
                if (displayItems[i].SiteName == previouslySelected)
                {
                    SitesListBox.SelectedIndex = i;
                    break;
                }
            }
        }
        bool vaultIsEmpty = allSites.Count == 0;
        bool searchHasNoMatches = !vaultIsEmpty && !string.IsNullOrEmpty(query) && visibleSites.Count == 0;
        EmptyVaultText.Visibility = vaultIsEmpty ? Visibility.Visible : Visibility.Collapsed;
        if (searchHasNoMatches)
        {
            NoSearchResultsText.Text = $"No saved sites match '{query}'.";
            NoSearchResultsText.Visibility = Visibility.Visible;
        }
        else
        {
            NoSearchResultsText.Visibility = Visibility.Collapsed;
        }
    }
    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (SearchPlaceholder != null)
            SearchPlaceholder.Visibility = string.IsNullOrEmpty(SearchBox.Text)
                ? Visibility.Visible
                : Visibility.Collapsed;
        RefreshSitesList();
    }
    private void SitesListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (SitesListBox.SelectedItem is not SiteDisplayItem item)
            return;
        string site = item.SiteName;
        if (_vault.Entries.TryGetValue(site, out Entry? entry))
        {
            _loadedSite = site;
            SiteTextBox.Text = site;
            WebsiteTextBox.Text = entry.Website;
            UsernameTextBox.Text = entry.Username;
            SetPasswordFieldValue(entry.GetPassword());
            DetailAvatar.Background = GetAvatarBrush(site);
            DetailAvatarLetter.Text = GetAvatarLetter(site);
            DetailSiteTitle.Text = site;
            ShowDetailPanel();
            VaultStatusText.Foreground = (Brush)FindResource("SubtleTextBrush");
            VaultStatusText.Text = $"Editing '{site}'.";
        }
    }
    private void NewEntryButton_Click(object sender, RoutedEventArgs e)
    {
        SitesListBox.SelectedItem = null;
        ClearDetailFields();
        DetailAvatar.Background = (Brush)FindResource("AccentBrush");
        DetailAvatarLetter.Text = "+";
        DetailSiteTitle.Text = "New Entry";
        ShowDetailPanel();
        VaultStatusText.Foreground = (Brush)FindResource("SubtleTextBrush");
        VaultStatusText.Text = "Enter details for a new entry.";
        SiteTextBox.Focus();
    }
    private void ShowDetailPanel()
    {
        NoSelectionHintText.Visibility = Visibility.Collapsed;
        DetailPanel.Visibility = Visibility.Visible;
    }
    private void ShowNoSelectionHint()
    {
        DetailPanel.Visibility = Visibility.Collapsed;
        NoSelectionHintText.Visibility = Visibility.Visible;
    }
    private void ClearDetailFields()
    {
        _loadedSite = null;
        SiteTextBox.Clear();
        WebsiteTextBox.Clear();
        UsernameTextBox.Clear();
        SetPasswordFieldValue("");
        GeneratorHintText.Text = "";
        if (_passwordRevealed)
        {
            _passwordRevealed = false;
            PasswordRevealedBox.Visibility = Visibility.Collapsed;
            PasswordMaskedBox.Visibility = Visibility.Visible;
            TogglePasswordIcon.Source = new BitmapImage(new Uri("/Assets/show.png", UriKind.Relative));
        }
    }
    private string GetPasswordFieldValue() =>
        _passwordRevealed ? PasswordRevealedBox.Text : PasswordMaskedBox.Password;
    private void SetPasswordFieldValue(string value)
    {
        _suppressPasswordSync = true;
        PasswordMaskedBox.Password = value;
        PasswordRevealedBox.Text = value;
        _suppressPasswordSync = false;
    }
    private void PasswordMaskedBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (_suppressPasswordSync) return;
        _suppressPasswordSync = true;
        PasswordRevealedBox.Text = PasswordMaskedBox.Password;
        _suppressPasswordSync = false;
    }
    private void PasswordRevealedBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_suppressPasswordSync) return;
        _suppressPasswordSync = true;
        PasswordMaskedBox.Password = PasswordRevealedBox.Text;
        _suppressPasswordSync = false;
    }
    private void TogglePasswordVisibilityButton_Click(object sender, RoutedEventArgs e)
    {
        _passwordRevealed = !_passwordRevealed;
        if (_passwordRevealed)
        {
            PasswordRevealedBox.Text = PasswordMaskedBox.Password;
            PasswordMaskedBox.Visibility = Visibility.Collapsed;
            PasswordRevealedBox.Visibility = Visibility.Visible;
            TogglePasswordIcon.Source = new BitmapImage(new Uri("/Assets/hide.png", UriKind.Relative));
        }
        else
        {
            PasswordMaskedBox.Password = PasswordRevealedBox.Text;
            PasswordRevealedBox.Visibility = Visibility.Collapsed;
            PasswordMaskedBox.Visibility = Visibility.Visible;
            TogglePasswordIcon.Source = new BitmapImage(new Uri("/Assets/show.png", UriKind.Relative));
        }
    }
    private void GeneratePasswordButton_Click(object sender, RoutedEventArgs e)
        => OpenGenerator();
    private void OpenGenerator()
    {
        LengthSlider.Value = _generatorLength;
        UppercaseToggle.IsChecked = _useUppercase;
        LowercaseToggle.IsChecked = _useLowercase;
        DigitsToggle.IsChecked = _useDigits;
        SymbolsToggle.IsChecked = _useSymbols;
        LengthValueText.Text = _generatorLength.ToString();
        RegeneratePassword();
        GeneratorOverlay.Visibility = Visibility.Visible;
    }
    private void CloseGenerator()
    {
        GeneratorOverlay.Visibility = Visibility.Collapsed;
    }
    private void GeneratorBackdrop_MouseDown(object sender, MouseButtonEventArgs e)
        => CloseGenerator();
    private void LengthSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        _generatorLength = (int)e.NewValue;
        if (LengthValueText != null)
            LengthValueText.Text = _generatorLength.ToString();
        if (GeneratedPasswordText != null)
            RegeneratePassword();
    }
    private void ToggleCharType_Click(object sender, RoutedEventArgs e)
    {
        _useUppercase = UppercaseToggle.IsChecked == true;
        _useLowercase = LowercaseToggle.IsChecked == true;
        _useDigits = DigitsToggle.IsChecked == true;
        _useSymbols = SymbolsToggle.IsChecked == true;
        RegeneratePassword();
    }
    private void RefreshGeneratedPassword_Click(object sender, RoutedEventArgs e)
        => RegeneratePassword();
    private void UseGeneratedPassword_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(_generatedPassword)) return;
        SetPasswordFieldValue(_generatedPassword);
        CloseGenerator();
        GeneratorHintText.Text = $"Generated a {_generatorLength}-char password. Remember to Save.";
    }
    private void RegeneratePassword()
    {
        string charset = BuildCharset();
        if (charset.Length == 0)
        {
            _generatedPassword = "";
            GeneratedPasswordText.Text = "Select at least one character type";
            return;
        }
        _generatedPassword = GenerateSecurePassword(_generatorLength, charset);
        GeneratedPasswordText.Text = _generatedPassword;
    }
    private string BuildCharset()
    {
        var sb = new StringBuilder();
        if (_useUppercase) sb.Append("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        if (_useLowercase) sb.Append("abcdefghijklmnopqrstuvwxyz");
        if (_useDigits) sb.Append("0123456789");
        if (_useSymbols) sb.Append("!@#$%^&*()-_=+");
        return sb.ToString();
    }
    private static string GenerateSecurePassword(int length, string charset)
    {
        var chars = new char[length];
        for (int i = 0; i < length; i++)
            chars[i] = charset[RandomNumberGenerator.GetInt32(charset.Length)];
        return new string(chars);
    }
    private void SaveEntryButton_Click(object sender, RoutedEventArgs e)
    {
        string site = SiteTextBox.Text.Trim();
        string websiteUrl = WebsiteTextBox.Text.Trim();
        string username = UsernameTextBox.Text.Trim();
        string password = GetPasswordFieldValue();
        if (string.IsNullOrWhiteSpace(site))
        {
            SetVaultStatus("Site name can't be empty.", isError: true);
            return;
        }
        if (string.IsNullOrEmpty(password))
        {
            SetVaultStatus("Password can't be empty.", isError: true);
            return;
        }
        if (_loadedSite != null && _loadedSite != site)
        {
            _vault.DeleteEntry(_loadedSite);
        }
        _vault.AddOrUpdateEntry(site, username, password, websiteUrl);
        _loadedSite = site;
        DetailAvatar.Background = GetAvatarBrush(site);
        DetailAvatarLetter.Text = GetAvatarLetter(site);
        DetailSiteTitle.Text = site;
        RefreshSitesList();
        if (SitesListBox.ItemsSource is List<SiteDisplayItem> items)
        {
            for (int i = 0; i < items.Count; i++)
            {
                if (items[i].SiteName == site)
                {
                    SitesListBox.SelectedIndex = i;
                    break;
                }
            }
        }
        int duplicateCount = 0;
        List<string> duplicates = new();
        foreach (var kvp in _vault.Entries)
        {
            if (kvp.Key != site && kvp.Value.GetPassword() == password)
            {
                duplicateCount++;
                if (duplicates.Count < 3)
                {
                    duplicates.Add(kvp.Key);
                }
            }
        }
        if (duplicateCount > 0)
        {
            string dupSites = string.Join(", ", duplicates);
            if (duplicateCount > 3)
            {
                dupSites += $", and {duplicateCount - 3} more";
            }
            VaultStatusText.Foreground = (Brush)FindResource("WarningBrush");
            VaultStatusText.Text = $"Saved '{site}'. Warning: Password reused on {dupSites}.";
        }
        else
        {
            SetVaultStatus($"Saved '{site}'.", isError: false);
        }
    }
    private void DeleteEntryButton_Click(object sender, RoutedEventArgs e)
    {
        if (_loadedSite == null)
        {
            SetVaultStatus("Nothing selected to delete.", isError: true);
            return;
        }
        var result = MessageBox.Show(
            $"Delete the entry for '{_loadedSite}'? This can't be undone.",
            "Confirm delete",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (result != MessageBoxResult.Yes)
            return;
        string deletedSite = _loadedSite;
        _vault.DeleteEntry(_loadedSite);
        ClearDetailFields();
        ShowNoSelectionHint();
        RefreshSitesList();
        SetVaultStatus($"Deleted '{deletedSite}'.", isError: false);
    }
    private void SetVaultStatus(string message, bool isError)
    {
        VaultStatusText.Foreground = isError
            ? (Brush)FindResource("ErrorBrush")
            : (Brush)FindResource("SuccessBrush");
        VaultStatusText.Text = message;
    }
    private void OpenBrowserButton_Click(object sender, RoutedEventArgs e)
    {
        string url = WebsiteTextBox.Text.Trim();
        if (string.IsNullOrEmpty(url)) return;
        if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && 
            !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            url = "https://" + url;
        }
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch
        {
            SetVaultStatus("Could not open URL.", isError: true);
        }
    }
    private void CopyUsernameButton_Click(object sender, RoutedEventArgs e)
    {
        string username = UsernameTextBox.Text.Trim();
        if (string.IsNullOrEmpty(username)) return;
        Clipboard.SetText(username);
        SetVaultStatus("Username copied.", isError: false);
    }
    private void CopyPasswordButton_Click(object sender, RoutedEventArgs e)
    {
        string password = GetPasswordFieldValue();
        if (string.IsNullOrEmpty(password))
            return;
        Clipboard.SetText(password);
        VaultStatusText.Foreground = (Brush)FindResource("SubtleTextBrush");
        VaultStatusText.Text = $"Password copied. Clipboard will clear in {ClipboardClearDelay.TotalSeconds:N0}s.";
        _clipboardClearTimer?.Stop();
        _clipboardClearTimer = new DispatcherTimer { Interval = ClipboardClearDelay };
        _clipboardClearTimer.Tick += (_, _) =>
        {
            _clipboardClearTimer!.Stop();
            try
            {
                if (Clipboard.ContainsText() && Clipboard.GetText() == password)
                    Clipboard.Clear();
            }
            catch (System.Runtime.InteropServices.COMException)
            {
            }
        };
        _clipboardClearTimer.Start();
    }
    private void ExportButton_Click(object sender, RoutedEventArgs e)
    {
        if (_vault.Entries.Count == 0)
        {
            SetVaultStatus("Vault is empty. Nothing to export.", isError: true);
            return;
        }
        var dialog = new SaveFileDialog
        {
            Filter = "JSON files (*.json)|*.json",
            FileName = "mysticvault_export.json"
        };
        if (dialog.ShowDialog() == true)
        {
            try
            {
                var exportList = _vault.Entries
                    .Select(kvp => new ExportEntry(kvp.Key, kvp.Value.Username, kvp.Value.GetPassword(), kvp.Value.Website))
                    .OrderBy(x => x.SiteName)
                    .ToList();
                string json = JsonSerializer.Serialize(exportList, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(dialog.FileName, json);
                SetVaultStatus($"Exported {exportList.Count} entries successfully.", isError: false);
            }
            catch
            {
                SetVaultStatus("Export failed.", isError: true);
            }
        }
    }
    private void ImportButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Filter = "JSON files (*.json)|*.json"
        };
        if (dialog.ShowDialog() == true)
        {
            try
            {
                string json = File.ReadAllText(dialog.FileName);
                var importList = JsonSerializer.Deserialize<List<ExportEntry>>(json);
                if (importList != null)
                {
                    foreach (var entry in importList)
                    {
                        _vault.AddOrUpdateEntry(entry.SiteName, entry.Username, entry.Password, entry.Website ?? "");
                    }
                    RefreshSitesList();
                    MessageBox.Show($"Imported {importList.Count} entries successfully.", "MysticVault", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch
            {
                MessageBox.Show("Import failed: Invalid file format.", "MysticVault", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
    private void BrowserExtractButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var extracted = BrowserExtractor.ExtractAll();
            if (extracted.Count > 0)
            {
                foreach (var cred in extracted)
                {
                    string siteName = "Browser: " + cred.Url;
                    try
                    {
                        if (Uri.TryCreate(cred.Url, UriKind.Absolute, out Uri? uri))
                        {
                            siteName = uri.Host;
                            if (siteName.StartsWith("www."))
                                siteName = siteName.Substring(4);
                        }
                    }
                    catch { }
                    _vault.AddOrUpdateEntry(siteName, cred.Username, cred.Password, cred.Url);
                }
                RefreshSitesList();
                MessageBox.Show($"Extracted {extracted.Count} entries from browsers.", "MysticVault", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show("No passwords found in browsers, or access was blocked.", "MysticVault", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Extraction error: {ex.Message}", "MysticVault", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
    private void LockButton_Click(object sender, RoutedEventArgs e)
    {
        LockVault();
    }
    private void LockVault()
    {
        _vault.Lock();
        ClearDetailFields();
        SitesListBox.ItemsSource = null;
        SearchBox.Clear();
        VaultPanel.Visibility = Visibility.Collapsed;
        LockPanel.Visibility = Visibility.Visible;
        StatusText.Text = "";
        UpdateLockScreenForVaultState();
    }
}