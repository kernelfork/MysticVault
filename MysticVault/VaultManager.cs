using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Konscious.Security.Cryptography;

namespace MysticVault;

public enum UnlockResult
{
    Success,
    IncorrectPassword,
    WrongMachineOrAccount,
    CorruptFile
}

public class VaultManager
{
    internal const string DbFile = "vault.dat";
    private const int SaltSizeBytes = 16;
    private const int KeySizeBytes = 32;
    private const int NonceSizeBytes = 12;
    private const int Argon2DegreeOfParallelism = 8;
    private const int Argon2Iterations = 10;
    private const int Argon2MemorySizeKb = 256 * 1024; 

    [System.Runtime.InteropServices.DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CryptProtectMemory(byte[] pDataIn, uint cbDataIn, uint dwFlags);

    [System.Runtime.InteropServices.DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CryptUnprotectMemory(byte[] pDataIn, uint cbDataIn, uint dwFlags);

    private const uint CRYPTPROTECTMEMORY_SAME_PROCESS = 0;

    private byte[]? _masterKey;
    private Dictionary<string, Entry> _entries = new();
    private byte[]? _cachedSalt;
    private byte[]? _cachedPassNonce;
    private byte[]? _cachedPassTag;
    private byte[]? _cachedPassEncryptedKey;
    private byte[]? _cachedDpapiEncryptedKey;

    public bool IsUnlocked => _masterKey != null;
    public static bool VaultExists() => File.Exists(DbFile);
    public static bool HasPasskey()
    {
        if (!VaultExists()) return false;
        try
        {
            string json = File.ReadAllText(DbFile);
            var vaultFile = JsonSerializer.Deserialize<VaultFile>(json);
            return vaultFile?.DpapiEncryptedMasterKey != null;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"HasPasskey: {ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }
    public IReadOnlyDictionary<string, Entry> Entries => _entries;

    public void InitializeNewVault(System.Security.SecureString masterPassword)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSizeBytes);
        byte[] vaultMasterKey = RandomNumberGenerator.GetBytes(KeySizeBytes);
        
        byte[] passwordKey = DeriveKeyFromPassword(masterPassword, salt);
        
        byte[] passNonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
        byte[] passEncryptedKey = new byte[KeySizeBytes];
        byte[] passTag = new byte[16];

        using (var aes = new AesGcm(passwordKey, passTag.Length))
        {
            aes.Encrypt(passNonce, vaultMasterKey, passEncryptedKey, passTag);
        }

        byte[] dpapiEncryptedKey = ProtectedData.Protect(vaultMasterKey, optionalEntropy: null, scope: DataProtectionScope.CurrentUser);

        CryptographicOperations.ZeroMemory(passwordKey);

        _masterKey = vaultMasterKey;
        CryptProtectMemory(_masterKey, (uint)_masterKey.Length, CRYPTPROTECTMEMORY_SAME_PROCESS);
        _entries = new Dictionary<string, Entry>();

        _cachedSalt = salt;
        _cachedPassNonce = passNonce;
        _cachedPassTag = passTag;
        _cachedPassEncryptedKey = passEncryptedKey;
        _cachedDpapiEncryptedKey = dpapiEncryptedKey;

        Save(salt, passNonce, passTag, passEncryptedKey, dpapiEncryptedKey);
    }

    public UnlockResult UnlockWithPassword(System.Security.SecureString masterPassword)
    {
        VaultFile vaultFile;
        try
        {
            string json = File.ReadAllText(DbFile);
            vaultFile = JsonSerializer.Deserialize<VaultFile>(json) ?? throw new InvalidOperationException();
        }
        catch { return UnlockResult.CorruptFile; }

        if (vaultFile.PasswordEncryptedMasterKey == null || vaultFile.DpapiEncryptedMasterKey == null)
            return UnlockResult.CorruptFile;

        try
        {
            byte[] dpapiTest = Convert.FromBase64String(vaultFile.DpapiEncryptedMasterKey);
            byte[] testUnprotect = ProtectedData.Unprotect(dpapiTest, optionalEntropy: null, scope: DataProtectionScope.CurrentUser);
            CryptographicOperations.ZeroMemory(testUnprotect);
        }
        catch
        {
            return UnlockResult.WrongMachineOrAccount;
        }

        byte[] salt = Convert.FromBase64String(vaultFile.Salt);
        byte[] passwordKey = DeriveKeyFromPassword(masterPassword, salt);
        byte[] passNonce = Convert.FromBase64String(vaultFile.PasswordNonce!);
        byte[] passTag = Convert.FromBase64String(vaultFile.PasswordTag!);
        byte[] passEncryptedKey = Convert.FromBase64String(vaultFile.PasswordEncryptedMasterKey);

        byte[] vaultMasterKey = new byte[KeySizeBytes];
        try
        {
            using var aes = new AesGcm(passwordKey, passTag.Length);
            aes.Decrypt(passNonce, passEncryptedKey, passTag, vaultMasterKey);
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(passwordKey);
            return UnlockResult.IncorrectPassword;
        }

        CryptographicOperations.ZeroMemory(passwordKey);

        string dataToSign = vaultFile.Salt + vaultFile.Nonce + vaultFile.Tag + vaultFile.Ciphertext;
        byte[] expectedHmac;
        using (var hmacSha = new HMACSHA256(vaultMasterKey))
        {
            expectedHmac = hmacSha.ComputeHash(Encoding.UTF8.GetBytes(dataToSign));
        }
        if (vaultFile.HmacSignature != null && vaultFile.HmacSignature != Convert.ToBase64String(expectedHmac))
        {
            CryptographicOperations.ZeroMemory(vaultMasterKey);
            return UnlockResult.CorruptFile;
        }

        try
        {
            _entries = Decrypt(vaultFile, vaultMasterKey);
            _masterKey = vaultMasterKey;
            CryptProtectMemory(_masterKey, (uint)_masterKey.Length, CRYPTPROTECTMEMORY_SAME_PROCESS);
            _cachedSalt = salt;
            _cachedPassNonce = passNonce;
            _cachedPassTag = passTag;
            _cachedPassEncryptedKey = passEncryptedKey;
            _cachedDpapiEncryptedKey = vaultFile.DpapiEncryptedMasterKey != null ? Convert.FromBase64String(vaultFile.DpapiEncryptedMasterKey) : null;
            return UnlockResult.Success;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(vaultMasterKey);
            return UnlockResult.CorruptFile;
        }
    }

    public UnlockResult UnlockWithPasskey()
    {
        VaultFile vaultFile;
        try
        {
            string json = File.ReadAllText(DbFile);
            vaultFile = JsonSerializer.Deserialize<VaultFile>(json) ?? throw new InvalidOperationException();
        }
        catch { return UnlockResult.CorruptFile; }

        if (vaultFile.DpapiEncryptedMasterKey == null)
            return UnlockResult.WrongMachineOrAccount;

        byte[] dpapiEncryptedKey = Convert.FromBase64String(vaultFile.DpapiEncryptedMasterKey);
        byte[] vaultMasterKey;
        try
        {
            vaultMasterKey = ProtectedData.Unprotect(dpapiEncryptedKey, optionalEntropy: null, scope: DataProtectionScope.CurrentUser);
        }
        catch (CryptographicException)
        {
            return UnlockResult.WrongMachineOrAccount;
        }

        string dataToSign = vaultFile.Salt + vaultFile.Nonce + vaultFile.Tag + vaultFile.Ciphertext;
        byte[] expectedHmac;
        using (var hmacSha = new HMACSHA256(vaultMasterKey))
        {
            expectedHmac = hmacSha.ComputeHash(Encoding.UTF8.GetBytes(dataToSign));
        }
        if (vaultFile.HmacSignature != null && vaultFile.HmacSignature != Convert.ToBase64String(expectedHmac))
        {
            CryptographicOperations.ZeroMemory(vaultMasterKey);
            return UnlockResult.CorruptFile;
        }

        byte[] passSalt = Convert.FromBase64String(vaultFile.Salt);
        byte[] passNonce = Convert.FromBase64String(vaultFile.PasswordNonce!);
        byte[] passTag = Convert.FromBase64String(vaultFile.PasswordTag!);
        byte[] passEncryptedKey = Convert.FromBase64String(vaultFile.PasswordEncryptedMasterKey!);

        try
        {
            _entries = Decrypt(vaultFile, vaultMasterKey);
            _masterKey = vaultMasterKey;
            CryptProtectMemory(_masterKey, (uint)_masterKey.Length, CRYPTPROTECTMEMORY_SAME_PROCESS);
            _cachedSalt = passSalt;
            _cachedPassNonce = passNonce;
            _cachedPassTag = passTag;
            _cachedPassEncryptedKey = passEncryptedKey;
            _cachedDpapiEncryptedKey = vaultFile.DpapiEncryptedMasterKey != null ? Convert.FromBase64String(vaultFile.DpapiEncryptedMasterKey) : null;
            return UnlockResult.Success;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(vaultMasterKey);
            return UnlockResult.CorruptFile;
        }
    }

    public void Save()
    {
        if (_masterKey == null) throw new InvalidOperationException("Vault is locked");

        byte[]? salt = _cachedSalt;
        byte[]? passNonce = _cachedPassNonce;
        byte[]? passTag = _cachedPassTag;
        byte[]? passEncryptedKey = _cachedPassEncryptedKey;
        byte[]? dpapiEncryptedKey = _cachedDpapiEncryptedKey;

        if (salt == null || passNonce == null || passTag == null || passEncryptedKey == null)
        {
            VaultFile currentVault;
            try
            {
                string json = File.ReadAllText(DbFile);
                currentVault = JsonSerializer.Deserialize<VaultFile>(json) ?? throw new InvalidOperationException();
            }
            catch { throw new InvalidOperationException("Failed to read existing vault header"); }

            salt = Convert.FromBase64String(currentVault.Salt);
            passNonce = Convert.FromBase64String(currentVault.PasswordNonce!);
            passTag = Convert.FromBase64String(currentVault.PasswordTag!);
            passEncryptedKey = Convert.FromBase64String(currentVault.PasswordEncryptedMasterKey!);
            dpapiEncryptedKey = currentVault.DpapiEncryptedMasterKey != null ? Convert.FromBase64String(currentVault.DpapiEncryptedMasterKey) : null;
        }

        if (dpapiEncryptedKey == null)
        {
            CryptUnprotectMemory(_masterKey, (uint)_masterKey.Length, CRYPTPROTECTMEMORY_SAME_PROCESS);
            dpapiEncryptedKey = ProtectedData.Protect(_masterKey, null, DataProtectionScope.CurrentUser);
            CryptProtectMemory(_masterKey, (uint)_masterKey.Length, CRYPTPROTECTMEMORY_SAME_PROCESS);
            _cachedDpapiEncryptedKey = dpapiEncryptedKey;
        }

        Save(salt, passNonce, passTag, passEncryptedKey, dpapiEncryptedKey);
    }

    private void Save(byte[] salt, byte[] passNonce, byte[] passTag, byte[] passEncryptedKey, byte[]? dpapiEncryptedKey)
    {
        if (_masterKey == null) throw new InvalidOperationException("Vault is locked.");

        CryptUnprotectMemory(_masterKey, (uint)_masterKey.Length, CRYPTPROTECTMEMORY_SAME_PROCESS);
        try
        {
            string json = JsonSerializer.Serialize(_entries);
            byte[] plaintext = Encoding.UTF8.GetBytes(json);

            byte[] nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];

            using (var aes = new AesGcm(_masterKey, tag.Length))
            {
                aes.Encrypt(nonce, plaintext, ciphertext, tag);
            }

            string saltBase64 = Convert.ToBase64String(salt);
            string nonceBase64 = Convert.ToBase64String(nonce);
            string tagBase64 = Convert.ToBase64String(tag);
            string cipherBase64 = Convert.ToBase64String(ciphertext);

            string dataToSign = saltBase64 + nonceBase64 + tagBase64 + cipherBase64;
            byte[] hmac;
            using (var hmacSha = new HMACSHA256(_masterKey))
            {
                hmac = hmacSha.ComputeHash(Encoding.UTF8.GetBytes(dataToSign));
            }

            var vaultFile = new VaultFile(
                Salt: saltBase64,
                Nonce: nonceBase64,
                Tag: tagBase64,
                Ciphertext: cipherBase64,
                PasswordEncryptedMasterKey: Convert.ToBase64String(passEncryptedKey),
                PasswordNonce: Convert.ToBase64String(passNonce),
                PasswordTag: Convert.ToBase64String(passTag),
                DpapiEncryptedMasterKey: dpapiEncryptedKey != null ? Convert.ToBase64String(dpapiEncryptedKey) : null,
                HmacSignature: Convert.ToBase64String(hmac)
            );

            string output = JsonSerializer.Serialize(vaultFile, new JsonSerializerOptions { WriteIndented = true });
            string tempFile = DbFile + ".tmp";
            File.WriteAllText(tempFile, output);
            File.Move(tempFile, DbFile, overwrite: true);

            CryptographicOperations.ZeroMemory(plaintext);
        }
        finally
        {
            CryptProtectMemory(_masterKey, (uint)_masterKey.Length, CRYPTPROTECTMEMORY_SAME_PROCESS);
        }
    }

    public void AddOrUpdateEntry(string siteName, string username, string password, string url = "")
    {
        if (_masterKey == null) throw new InvalidOperationException("Vault is locked.");
        _entries[siteName] = new Entry(username, password, url);
        Save();
    }

    public void DeleteEntry(string siteName)
    {
        if (_masterKey == null) throw new InvalidOperationException("Vault is locked.");
        if (_entries.Remove(siteName))
        {
            Save();
        }
    }

    public void Lock()
    {
        if (_masterKey != null)
        {
            CryptographicOperations.ZeroMemory(_masterKey);
            _masterKey = null;
        }
        _entries.Clear();
        _cachedSalt = null;
        _cachedPassNonce = null;
        _cachedPassTag = null;
        _cachedPassEncryptedKey = null;
        _cachedDpapiEncryptedKey = null;
    }

    private byte[] DeriveKeyFromPassword(System.Security.SecureString password, byte[] salt)
    {
        IntPtr valuePtr = IntPtr.Zero;
        byte[] passwordBytes = new byte[password.Length * 2]; 
        int byteCount = 0;
        try
        {
            valuePtr = System.Runtime.InteropServices.Marshal.SecureStringToBSTR(password);
            unsafe
            {
                char* chars = (char*)valuePtr;
                fixed (byte* pBytes = passwordBytes)
                {
                    byteCount = Encoding.UTF8.GetBytes(chars, password.Length, pBytes, passwordBytes.Length);
                }
            }
        }
        finally
        {
            if (valuePtr != IntPtr.Zero)
            {
                System.Runtime.InteropServices.Marshal.ZeroFreeBSTR(valuePtr);
            }
        }

        byte[] finalPasswordBytes = new byte[byteCount];
        Array.Copy(passwordBytes, finalPasswordBytes, byteCount);
        CryptographicOperations.ZeroMemory(passwordBytes);

        using var argon2 = new Argon2id(finalPasswordBytes)
        {
            Salt = salt,
            DegreeOfParallelism = Argon2DegreeOfParallelism,
            Iterations = Argon2Iterations,
            MemorySize = Argon2MemorySizeKb
        };
        byte[] key = argon2.GetBytes(KeySizeBytes);
        CryptographicOperations.ZeroMemory(finalPasswordBytes);
        return key;
    }

    private Dictionary<string, Entry> Decrypt(VaultFile vaultFile, byte[] key)
    {
        byte[] nonce = Convert.FromBase64String(vaultFile.Nonce);
        byte[] tag = Convert.FromBase64String(vaultFile.Tag);
        byte[] ciphertext = Convert.FromBase64String(vaultFile.Ciphertext);

        byte[] plaintext = new byte[ciphertext.Length];
        using (var aes = new AesGcm(key, tag.Length))
        {
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
        }

        string json = Encoding.UTF8.GetString(plaintext);
        CryptographicOperations.ZeroMemory(plaintext);

        var entries = JsonSerializer.Deserialize<Dictionary<string, Entry>>(json);
        return entries ?? new Dictionary<string, Entry>();
    }
}