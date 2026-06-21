using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace MysticVault;

public class SyncPayload
{
    public string Nonce { get; set; } = "";
    public string Ciphertext { get; set; } = "";
    public string Tag { get; set; } = "";
}

public class SyncManager
{
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private readonly VaultManager _vault;
    private byte[]? _ephemeralKey;

    public SyncManager(VaultManager vault)
    {
        _vault = vault;
    }

    public string StartServer()
    {
        _ephemeralKey = RandomNumberGenerator.GetBytes(32);
        
        string localIp = GetLocalIPAddress();
        string url = $"http://{localIp}:5555/";

        _listener = new TcpListener(IPAddress.Parse(localIp), 5555);
        _listener.Start();

        _cts = new CancellationTokenSource();
        Task.Run(() => AcceptRequests(_cts.Token));

        return url;
    }

    public void StopServer()
    {
        if (_cts != null)
        {
            _cts.Cancel();
            _cts = null;
        }
        if (_listener != null)
        {
            _listener.Stop();
            _listener = null;
        }
        if (_ephemeralKey != null)
        {
            CryptographicOperations.ZeroMemory(_ephemeralKey);
            _ephemeralKey = null;
        }
    }

    private string GetLocalIPAddress()
    {
        var host = Dns.GetHostEntry(Dns.GetHostName());
        foreach (var ip in host.AddressList)
        {
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                return ip.ToString();
            }
        }
        return "127.0.0.1";
    }

    private async Task AcceptRequests(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                var client = await _listener!.AcceptTcpClientAsync(token);
                _ = Task.Run(() => HandleClient(client), token);
            }
            catch
            {
                break;
            }
        }
    }

    private void HandleClient(TcpClient client)
    {
        try
        {
            using var stream = client.GetStream();
            using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
            string? line = reader.ReadLine();
            if (string.IsNullOrEmpty(line)) return;

            string[] parts = line.Split(' ');
            if (parts.Length < 2) return;
            string method = parts[0];
            string path = parts[1];

            while (!string.IsNullOrEmpty(line = reader.ReadLine()))
            {
            }

            string responseBody = "";
            string contentType = "text/html";
            string statusCode = "200 OK";

            if (path == "/")
            {
                responseBody = GetHtmlApp(Convert.ToBase64String(_ephemeralKey!));
                contentType = "text/html";
            }
            else if (path == "/api/vault")
            {
                responseBody = GetEncryptedVault();
                contentType = "application/json";
            }
            else
            {
                statusCode = "404 Not Found";
                responseBody = "Not Found";
                contentType = "text/plain";
            }

            byte[] bodyBytes = Encoding.UTF8.GetBytes(responseBody);
            
            string headers = $"HTTP/1.1 {statusCode}\r\n" +
                             $"Content-Type: {contentType}; charset=utf-8\r\n" +
                             $"Content-Length: {bodyBytes.Length}\r\n" +
                             "Connection: close\r\n\r\n";
                             
            byte[] headerBytes = Encoding.UTF8.GetBytes(headers);
            
            stream.Write(headerBytes, 0, headerBytes.Length);
            stream.Write(bodyBytes, 0, bodyBytes.Length);
        }
        catch
        {
        }
        finally
        {
            client.Close();
        }
    }

    private string GetEncryptedVault()
    {
        if (!_vault.IsUnlocked) return "{}";

        using var ms = new MemoryStream();
        using (var writer = new Utf8JsonWriter(ms))
        {
            writer.WriteStartObject();
            foreach (var kvp in _vault.Entries)
            {
                writer.WriteStartObject(kvp.Key);
                writer.WriteString("username", kvp.Value.Username);

                string pwd = kvp.Value.GetPassword();
                writer.WriteString("password", pwd);
                Entry.ZeroString(pwd);

                writer.WriteString("website", kvp.Value.Website);
                writer.WriteEndObject();
            }
            writer.WriteEndObject();
        }

        byte[] plaintext = ms.ToArray();

        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        using (var aes = new AesGcm(_ephemeralKey!, tag.Length))
        {
            aes.Encrypt(nonce, plaintext, ciphertext, tag);
        }

        var payload = new SyncPayload
        {
            Nonce = Convert.ToBase64String(nonce),
            Ciphertext = Convert.ToBase64String(ciphertext),
            Tag = Convert.ToBase64String(tag)
        };

        CryptographicOperations.ZeroMemory(plaintext);
        return JsonSerializer.Serialize(payload);
    }

    private string GetHtmlApp(string b64Key)
    {
        var html = @"<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""UTF-8"">
    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no"">
    <title>MysticVault</title>
    <style>
        :root { --bg: #121212; --card: #1E1E1E; --text: #E0E0E0; --accent: #BB86FC; }
        body { font-family: -apple-system, BlinkMacSystemFont, ""Segoe UI"", Roboto, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 20px; }
        h1 { text-align: center; color: var(--accent); }
        #search { width: 100%; padding: 15px; border-radius: 8px; border: none; background: var(--card); color: white; font-size: 16px; box-sizing: border-box; margin-bottom: 20px; }
        .entry { background: var(--card); padding: 15px; border-radius: 8px; margin-bottom: 10px; display: flex; flex-direction: column; gap: 5px; }
        .site { font-size: 18px; font-weight: bold; }
        .user { color: #888; font-size: 14px; }
        .pass-row { display: flex; justify-content: space-between; align-items: center; margin-top: 10px; }
        .pass { background: #2A2A2A; padding: 10px; border-radius: 4px; font-family: monospace; letter-spacing: 2px; flex-grow: 1; margin-right: 10px; overflow-x: auto; }
        .copy-btn { background: var(--accent); color: #000; border: none; padding: 10px 15px; border-radius: 4px; font-weight: bold; cursor: pointer; }
    </style>
</head>
<body>
    <h1>🔮 MysticVault</h1>
    <input type=""text"" id=""search"" placeholder=""Search passwords..."" autocomplete=""off"">
    <div id=""vault"">Loading secure vault...</div>

    <script>
        const B64_KEY = ""___KEY___"";

        async function init() {
            try {
                const keyStr = atob(B64_KEY);
                const keyBuf = new Uint8Array(keyStr.length);
                for(let i=0; i<keyStr.length; i++) keyBuf[i] = keyStr.charCodeAt(i);
                
                const cryptoKey = await window.crypto.subtle.importKey(
                    ""raw"", keyBuf, { name: ""AES-GCM"" }, false, [""decrypt""]
                );
                
                const res = await fetch('/api/vault');
                const payload = await res.json();
                
                const ivStr = atob(payload.Nonce);
                const iv = new Uint8Array(ivStr.length);
                for(let i=0; i<ivStr.length; i++) iv[i] = ivStr.charCodeAt(i);
                
                const cipherStr = atob(payload.Ciphertext);
                const cipherBuf = new Uint8Array(cipherStr.length);
                for(let i=0; i<cipherStr.length; i++) cipherBuf[i] = cipherStr.charCodeAt(i);
                
                const tagStr = atob(payload.Tag);
                const tagBuf = new Uint8Array(tagStr.length);
                for(let i=0; i<tagStr.length; i++) tagBuf[i] = tagStr.charCodeAt(i);
                
                const combined = new Uint8Array(cipherBuf.length + tagBuf.length);
                combined.set(cipherBuf);
                combined.set(tagBuf, cipherBuf.length);
                
                const decrypted = await window.crypto.subtle.decrypt(
                    { name: ""AES-GCM"", iv: iv }, cryptoKey, combined
                );
                
                const jsonText = new TextDecoder().decode(decrypted);
                window.vaultData = JSON.parse(jsonText);
                
                renderVault('');
                
                document.getElementById('search').addEventListener('input', (e) => {
                    renderVault(e.target.value.toLowerCase());
                });
                
            } catch (err) {
                document.getElementById('vault').innerText = ""Decryption failed. Ensure you are on the same Wi-Fi and scanned the correct code. Error: "" + err;
            }
        }

        function renderVault(query) {
            const container = document.getElementById('vault');
            container.innerHTML = '';
            
            window.renderedPasswords = [];
            let index = 0;
            
            for (const [site, data] of Object.entries(window.vaultData)) {
                if (query && !site.toLowerCase().includes(query) && !data.username.toLowerCase().includes(query)) continue;
                
                window.renderedPasswords.push(data.password);
                
                const div = document.createElement('div');
                div.className = 'entry';
                div.innerHTML = `
                    <div class=""site"">${site}</div>
                    <div class=""user"">${data.username}</div>
                    <div class=""pass-row"">
                        <div class=""pass"" onclick=""togglePass(this, ${index})"" data-hidden=""true"" style=""cursor: pointer;"">••••••••</div>
                        <button class=""copy-btn"" onclick=""copyText(${index})"">Copy</button>
                    </div>
                `;
                container.appendChild(div);
                index++;
            }
        }

        window.togglePass = function(el, idx) {
            if (el.getAttribute('data-hidden') === 'true') {
                el.innerText = window.renderedPasswords[idx];
                el.setAttribute('data-hidden', 'false');
            } else {
                el.innerText = '••••••••';
                el.setAttribute('data-hidden', 'true');
            }
        }

        window.copyText = function(idx) {
            const text = window.renderedPasswords[idx];
            try {
                if (navigator.clipboard && window.isSecureContext) {
                    navigator.clipboard.writeText(text);
                    alert('Copied to clipboard!');
                } else {
                    const textArea = document.createElement(""textarea"");
                    textArea.value = text;
                    textArea.style.position = ""fixed"";
                    textArea.style.left = ""-999999px"";
                    textArea.style.top = ""-999999px"";
                    document.body.appendChild(textArea);
                    textArea.focus();
                    textArea.select();
                    document.execCommand('copy');
                    textArea.remove();
                    alert('Copied to clipboard!');
                }
            } catch (err) {
                alert('Copy failed: ' + err);
            }
        }

        init();
    </script>
</body>
</html>";
        return html.Replace("___KEY___", b64Key);
    }
}
