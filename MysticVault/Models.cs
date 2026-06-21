using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
namespace MysticVault;

[JsonConverter(typeof(EntryJsonConverter))]
public class Entry
{
    public string Username { get; set; }
    public string Website { get; set; }
    public byte[] ProtectedPassword { get; set; } = Array.Empty<byte>();
    public byte[]? PasswordHash { get; set; }

    public Entry(string username, string password, string website = "")
    {
        Username = username;
        Website = website;
        SetPassword(password);
    }
    public Entry(string username, byte[] protectedPassword, string website)
    {
        Username = username;
        ProtectedPassword = protectedPassword;
        Website = website;
    }
    public void SetPassword(string password)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(password);
        ProtectedPassword = ProtectedData.Protect(bytes, null, DataProtectionScope.CurrentUser);
        PasswordHash = SHA256.HashData(bytes);
        CryptographicOperations.ZeroMemory(bytes);
    }
    public string GetPassword()
    {
        byte[] bytes = ProtectedData.Unprotect(ProtectedPassword, null, DataProtectionScope.CurrentUser);
        string pass = Encoding.UTF8.GetString(bytes);
        CryptographicOperations.ZeroMemory(bytes);
        return pass;
    }

    public void UsePassword(Action<string> action)
    {
        string password = GetPassword();
        try
        {
            action(password);
        }
        finally
        {
            ZeroString(password);
        }
    }

    public async Task UsePasswordAsync(Func<string, Task> action)
    {
        string password = GetPassword();
        try { await action(password); }
        finally { ZeroString(password); }
    }

    internal static unsafe void ZeroString(string? s)
    {
        if (string.IsNullOrEmpty(s)) return;
        fixed (char* p = s)
        {
            for (int i = 0; i < s.Length; i++)
                p[i] = '\0';
        }
    }
}
public class EntryJsonConverter : JsonConverter<Entry>
{
    public override Entry Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string username = "";
        string password = "";
        string website = "";
        using (JsonDocument doc = JsonDocument.ParseValue(ref reader))
        {
            var root = doc.RootElement;
            if (root.TryGetProperty("Username", out var userProp)) username = userProp.GetString() ?? "";
            if (root.TryGetProperty("Password", out var passProp)) password = passProp.GetString() ?? "";
            if (root.TryGetProperty("Website", out var webProp)) website = webProp.GetString() ?? "";
        }
        return new Entry(username, password, website);
    }
    public override void Write(Utf8JsonWriter writer, Entry value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        writer.WriteString("Username", value.Username);
        writer.WriteString("Password", value.GetPassword());
        writer.WriteString("Website", value.Website);
        writer.WriteString("PasswordHash", Convert.ToBase64String(value.PasswordHash ?? SHA256.HashData(Encoding.UTF8.GetBytes(value.GetPassword()))));
        writer.WriteEndObject();
    }
}
public record VaultFile(
    string Salt,
    string Nonce,
    string Tag,
    string Ciphertext,
    string? PasswordEncryptedMasterKey,
    string? PasswordNonce,
    string? PasswordTag,
    string? DpapiEncryptedMasterKey,
    string? HmacSignature
);