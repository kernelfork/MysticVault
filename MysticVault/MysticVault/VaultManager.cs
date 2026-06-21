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
    private const string DbFile = "vault.dat";
    private const int SaltSizeBytes = 16;
    private const int KeySizeBytes = 32;
    private const int MachineKeySizeBytes = 32;
    private const int NonceSizeBytes = 12;
    private const int Argon2DegreeOfParallelism = 8;
    private const int Argon2Iterations = 4;
    private const int Argon2MemorySizeKb = 64 * 1024; 
    private byte[]? _key;
    private byte[]? _salt;
    private byte[]? _protectedMachineKey;
    private Dictionary<string, Entry> _entries = new();
    public bool IsUnlocked => _key != null;
    public static bool VaultExists() => File.Exists(DbFile);
    public IReadOnlyDictionary<string, Entry> Entries => _entries;
    public void CreateVault(string masterPassword)
    {
        _salt = RandomNumberGenerator.GetBytes(SaltSizeBytes);
        byte[] passwordKey = DeriveKeyFromPassword(masterPassword, _salt);
        byte[] machineKey = RandomNumberGenerator.GetBytes(MachineKeySizeBytes);
        _protectedMachineKey = ProtectedData.Protect(
            machineKey, optionalEntropy: null, scope: DataProtectionScope.CurrentUser);
        _key = CombineKeys(passwordKey, machineKey);
        CryptographicOperations.ZeroMemory(passwordKey);
        CryptographicOperations.ZeroMemory(machineKey);
        _entries = new Dictionary<string, Entry>();
        Save();
    }
    public UnlockResult Unlock(string masterPassword)
    {
        VaultFile vaultFile;
        try
        {
            string json = File.ReadAllText(DbFile);
            vaultFile = JsonSerializer.Deserialize<VaultFile>(json)
                ?? throw new InvalidOperationException();
        }
        catch
        {
            return UnlockResult.CorruptFile;
        }
        byte[] salt = Convert.FromBase64String(vaultFile.Salt);
        byte[] protectedMachineKey = Convert.FromBase64String(vaultFile.ProtectedMachineKey);
        byte[] passwordKey = DeriveKeyFromPassword(masterPassword, salt);
        byte[] machineKey;
        try
        {
            machineKey = ProtectedData.Unprotect(
                protectedMachineKey, optionalEntropy: null, scope: DataProtectionScope.CurrentUser);
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(passwordKey);
            return UnlockResult.WrongMachineOrAccount;
        }
        byte[] combinedKey = CombineKeys(passwordKey, machineKey);
        CryptographicOperations.ZeroMemory(passwordKey);
        CryptographicOperations.ZeroMemory(machineKey);
        try
        {
            _entries = Decrypt(vaultFile, combinedKey);
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(combinedKey);
            return UnlockResult.IncorrectPassword;
        }
        _salt = salt;
        _protectedMachineKey = protectedMachineKey;
        _key = combinedKey;
        return UnlockResult.Success;
    }
    public void Lock()
    {
        if (_key != null)
        {
            CryptographicOperations.ZeroMemory(_key);
            _key = null;
        }
        _entries = new Dictionary<string, Entry>();
    }
    public void AddOrUpdateEntry(string site, string username, string password, string website = "")
    {
        EnsureUnlocked();
        _entries[site] = new Entry(username, password, website);
        Save();
    }
    public void DeleteEntry(string site)
    {
        EnsureUnlocked();
        _entries.Remove(site);
        Save();
    }
    private void EnsureUnlocked()
    {
        if (_key == null)
        {
            throw new InvalidOperationException("Vault is locked.");
        }
    }
    private static byte[] DeriveKeyFromPassword(string password, byte[] salt)
    {
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        try
        {
            using var argon2 = new Argon2id(passwordBytes)
            {
                Salt = salt,
                DegreeOfParallelism = Argon2DegreeOfParallelism,
                Iterations = Argon2Iterations,
                MemorySize = Argon2MemorySizeKb
            };
            return argon2.GetBytes(KeySizeBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }
    private static byte[] CombineKeys(byte[] passwordKey, byte[] machineKey)
    {
        byte[] combinedInput = new byte[passwordKey.Length + machineKey.Length];
        Buffer.BlockCopy(passwordKey, 0, combinedInput, 0, passwordKey.Length);
        Buffer.BlockCopy(machineKey, 0, combinedInput, passwordKey.Length, machineKey.Length);
        try
        {
            return HKDF.DeriveKey(
                HashAlgorithmName.SHA256,
                ikm: combinedInput,
                outputLength: KeySizeBytes,
                info: Encoding.UTF8.GetBytes("MysticVault-vault-key-v1"));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(combinedInput);
        }
    }
    private void Save()
    {
        EnsureUnlocked();
        string json = JsonSerializer.Serialize(_entries);
        byte[] plaintext = Encoding.UTF8.GetBytes(json);
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];
        using var aes = new AesGcm(_key!, tag.Length);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);
        var vaultFile = new VaultFile(
            Salt: Convert.ToBase64String(_salt!),
            Nonce: Convert.ToBase64String(nonce),
            Tag: Convert.ToBase64String(tag),
            Ciphertext: Convert.ToBase64String(ciphertext),
            ProtectedMachineKey: Convert.ToBase64String(_protectedMachineKey!)
        );
        File.WriteAllText(DbFile, JsonSerializer.Serialize(vaultFile));
        CryptographicOperations.ZeroMemory(plaintext);
    }
    private static Dictionary<string, Entry> Decrypt(VaultFile vaultFile, byte[] key)
    {
        byte[] nonce = Convert.FromBase64String(vaultFile.Nonce);
        byte[] tag = Convert.FromBase64String(vaultFile.Tag);
        byte[] ciphertext = Convert.FromBase64String(vaultFile.Ciphertext);
        byte[] plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(key, tag.Length);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        string json = Encoding.UTF8.GetString(plaintext);
        CryptographicOperations.ZeroMemory(plaintext);
        return JsonSerializer.Deserialize<Dictionary<string, Entry>>(json)
            ?? new Dictionary<string, Entry>();
    }
}