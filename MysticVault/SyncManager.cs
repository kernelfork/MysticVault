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

    private byte[] DeriveKeyStream(byte[] key, byte[] nonce, int length)
    {
        byte[] output = new byte[length];
        int counter = 0;
        int offset = 0;
        while (offset < length)
        {
            byte[] blockInput = new byte[key.Length + nonce.Length + 4];
            Buffer.BlockCopy(key, 0, blockInput, 0, key.Length);
            Buffer.BlockCopy(nonce, 0, blockInput, key.Length, nonce.Length);
            byte[] counterBytes = BitConverter.GetBytes(counter++);
            Buffer.BlockCopy(counterBytes, 0, blockInput, key.Length + nonce.Length, 4);

            byte[] hash = SHA256.HashData(blockInput);
            int copyLen = Math.Min(hash.Length, length - offset);
            Buffer.BlockCopy(hash, 0, output, offset, copyLen);
            offset += copyLen;
        }
        return output;
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
        byte[] keystream = DeriveKeyStream(_ephemeralKey!, nonce, plaintext.Length);
        byte[] ciphertext = new byte[plaintext.Length];
        for (int i = 0; i < plaintext.Length; i++)
            ciphertext[i] = (byte)(plaintext[i] ^ keystream[i]);

        byte[] tag;
        using (var hmac = new HMACSHA256(_ephemeralKey!))
            tag = hmac.ComputeHash(ciphertext);

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

        function b64ToBytes(s) {
            const str = atob(s);
            const b = new Uint8Array(str.length);
            for (let i = 0; i < str.length; i++) b[i] = str.charCodeAt(i);
            return b;
        }

        function ctEq(a, b) {
            if (a.length !== b.length) return false;
            let d = 0;
            for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
            return d === 0;
        }

        function sha256(d) {
            const K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
            const H0 = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
            const blen = d.length * 8;
            const pad = ((d.length + 9 + 63) & ~63) >>> 0;
            const m = new Uint8Array(pad);
            m.set(d);
            m[d.length] = 0x80;
            const dv = new DataView(m.buffer);
            dv.setUint32(pad - 8, 0, false);
            dv.setUint32(pad - 4, blen, false);
            const W = new Uint32Array(64);
            const H = H0.slice();
            const rr = (x, n) => (x >>> n) | (x << (32 - n));
            for (let b = 0; b < pad; b += 64) {
                for (let t = 0; t < 16; t++) W[t] = dv.getUint32(b + t * 4, false);
                for (let t = 16; t < 64; t++) {
                    const w0 = rr(W[t-15],7) ^ rr(W[t-15],18) ^ (W[t-15]>>>3);
                    const w1 = rr(W[t-2],17) ^ rr(W[t-2],19) ^ (W[t-2]>>>10);
                    W[t] = (W[t-16] + w0 + W[t-7] + w1) | 0;
                }
                let a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
                for (let t = 0; t < 64; t++) {
                    const S1 = rr(e,6) ^ rr(e,11) ^ rr(e,25);
                    const ch = (e & f) ^ ((~e) & g);
                    const t1 = (h + S1 + ch + K[t] + W[t]) | 0;
                    const S0 = rr(a,2) ^ rr(a,13) ^ rr(a,22);
                    const maj = (a & b) ^ (a & c) ^ (b & c);
                    const t2 = (S0 + maj) | 0;
                    h=g; g=f; f=e; e=(d+t1)|0; d=c; c=b; b=a; a=(t1+t2)|0;
                }
                H[0]=(H[0]+a)|0; H[1]=(H[1]+b)|0; H[2]=(H[2]+c)|0; H[3]=(H[3]+d)|0;
                H[4]=(H[4]+e)|0; H[5]=(H[5]+f)|0; H[6]=(H[6]+g)|0; H[7]=(H[7]+h)|0;
            }
            const out = new Uint8Array(32);
            const odv = new DataView(out.buffer);
            for (let i = 0; i < 8; i++) odv.setUint32(i * 4, H[i], false);
            return out;
        }

        function hmacSha256(key, msg) {
            if (key.length > 64) key = sha256(key);
            const kp = new Uint8Array(64);
            kp.set(key);
            const ipad = new Uint8Array(64);
            const opad = new Uint8Array(64);
            for (let i = 0; i < 64; i++) {
                ipad[i] = kp[i] ^ 0x36;
                opad[i] = kp[i] ^ 0x5c;
            }
            const inner = new Uint8Array(64 + msg.length);
            inner.set(ipad);
            inner.set(msg, 64);
            const ih = sha256(inner);
            const outer = new Uint8Array(64 + 32);
            outer.set(opad);
            outer.set(ih, 64);
            return sha256(outer);
        }

        function keyStream(key, nonce, len) {
            const inplen = key.length + nonce.length + 4;
            const blocks = Math.ceil(len / 32);
            const out = new Uint8Array(blocks * 32);
            const inp = new Uint8Array(inplen);
            inp.set(key);
            inp.set(nonce, key.length);
            const dv = new DataView(inp.buffer);
            for (let i = 0; i < blocks; i++) {
                dv.setUint32(key.length + nonce.length, i, true);
                const h = sha256(inp);
                out.set(h, i * 32);
            }
            return out.slice(0, len);
        }

        async function init() {
            try {
                const key = b64ToBytes(B64_KEY);
                const res = await fetch('/api/vault');
                const payload = await res.json();

                const nonce = b64ToBytes(payload.Nonce);
                const ciphertext = b64ToBytes(payload.Ciphertext);
                const tag = b64ToBytes(payload.Tag);

                const expected = hmacSha256(key, ciphertext);
                if (!ctEq(tag, expected)) {
                    document.getElementById('vault').innerText = 'Integrity check failed.';
                    return;
                }

                const ks = keyStream(key, nonce, ciphertext.length);
                const pt = new Uint8Array(ciphertext.length);
                for (let i = 0; i < ciphertext.length; i++) pt[i] = ciphertext[i] ^ ks[i];

                const jsonText = new TextDecoder().decode(pt);
                window.vaultData = JSON.parse(jsonText);

                renderVault('');

                document.getElementById('search').addEventListener('input', (e) => {
                    renderVault(e.target.value.toLowerCase());
                });

            } catch (err) {
                document.getElementById('vault').innerText = 'Decryption failed: ' + err;
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
