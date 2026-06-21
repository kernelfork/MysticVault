using System;
using System.Runtime.InteropServices;
using System.Text;

namespace MysticVault;

internal static class NssHelper
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int NSS_Init(string configdir);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int NSS_Shutdown();

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int PK11SDR_Decrypt(ref SECItem data, ref SECItem result, IntPtr cx);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void SECITEM_ZfreeItem(ref SECItem item, bool freeItem);

    [StructLayout(LayoutKind.Sequential)]
    public struct SECItem
    {
        public int type;
        public IntPtr data;
        public int len;
    }

    public static string Decrypt(string base64Encrypted, PK11SDR_Decrypt decryptFunc, SECITEM_ZfreeItem freeFunc)
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
                freeFunc(ref outItem, false);
            Marshal.FreeHGlobal(unmanagedPointer);
        }

        return decryptedStr;
    }
}
