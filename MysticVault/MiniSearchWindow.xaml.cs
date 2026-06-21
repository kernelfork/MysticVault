using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace MysticVault;

public partial class MiniSearchWindow : Window
{
    private readonly VaultManager _vault;

    public MiniSearchWindow(VaultManager vault)
    {
        InitializeComponent();
        _vault = vault;
        Loaded += (s, e) => { SearchBox.Focus(); PopulateList(""); };
        Deactivated += (s, e) => Hide();
        IsVisibleChanged += (s, e) => 
        { 
            if (IsVisible) 
            {
                SearchBox.Text = "";
                SearchBox.Focus(); 
                PopulateList(""); 
            }
        };
    }

    private void Window_PreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == Key.Escape)
        {
            Hide();
            e.Handled = true;
        }
    }

    private void PopulateList(string query)
    {
        if (!_vault.IsUnlocked)
        {
            ResultsList.ItemsSource = null;
            return;
        }

        var results = _vault.Entries
            .Where(kvp => string.IsNullOrWhiteSpace(query) || 
                          kvp.Key.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                          kvp.Value.Username.Contains(query, StringComparison.OrdinalIgnoreCase))
            .ToList();

        ResultsList.ItemsSource = results;
        if (results.Any())
            ResultsList.SelectedIndex = 0;
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        PopulateList(SearchBox.Text);
    }

    private void SearchBox_PreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == Key.Down)
        {
            if (ResultsList.Items.Count > 0)
            {
                int next = ResultsList.SelectedIndex + 1;
                if (next < ResultsList.Items.Count)
                {
                    ResultsList.SelectedIndex = next;
                    ResultsList.ScrollIntoView(ResultsList.SelectedItem);
                }
            }
            e.Handled = true;
        }
        else if (e.Key == Key.Up)
        {
            if (ResultsList.Items.Count > 0)
            {
                int prev = ResultsList.SelectedIndex - 1;
                if (prev >= 0)
                {
                    ResultsList.SelectedIndex = prev;
                    ResultsList.ScrollIntoView(ResultsList.SelectedItem);
                }
            }
            e.Handled = true;
        }
        else if (e.Key == Key.Enter)
        {
            if (ResultsList.SelectedItem is KeyValuePair<string, Entry> selected)
                ExecuteAutoType(selected.Key);
            e.Handled = true;
        }
    }

    private void ResultsList_PreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            if (ResultsList.SelectedItem is KeyValuePair<string, Entry> selected)
                ExecuteAutoType(selected.Key);
            e.Handled = true;
        }
    }

    private void ResultsList_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (ResultsList.SelectedItem is KeyValuePair<string, Entry> selected)
            ExecuteAutoType(selected.Key);
    }

    private async void ExecuteAutoType(string siteName)
    {
        Hide();
        await Task.Delay(200);

        if (_vault.Entries.TryGetValue(siteName, out var entry))
        {
            string password = entry.GetPassword();
            await InputSimulator.TypeTextAsync(entry.Username);
            await InputSimulator.SendKeyAsync(InputSimulator.VK_TAB);
            await InputSimulator.TypeTextAsync(password);
            await InputSimulator.SendKeyAsync(InputSimulator.VK_RETURN);
        }
    }
    
    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        e.Cancel = true;
        Hide();
    }
}
