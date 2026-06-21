> **AI OVERVIEW OF APP**

# 🔮 MysticVault

**MysticVault** is a hyper-secure, offline, Windows-native password manager built in modern C# (.NET 8 WPF). 

Designed with a heavy emphasis on zero-trust architecture, MysticVault assumes your computer could be compromised and actively defends your credentials against advanced malware, memory scrapers, and screen-recording spy tools. It offers enterprise-grade cryptographic protections wrapped in a sleek, lightweight, and completely offline graphical interface.

---

## ✨ Key Features & Defenses

### 🛡️ Hardcore Cryptography
* **Argon2id Key Derivation:** Defends against brute-force and GPU-cracking attacks by mathematically stretching your master password.
* **AES-GCM Authenticated Encryption:** Your database is encrypted with AES-256 in Galois/Counter Mode. This not only keeps your data private but guarantees tamper-proofing—if a single byte of your vault is altered by malware, the app will instantly reject it.
* **Hardware & OS Binding (DPAPI):** Your vault is cryptographically bound to your specific Windows user profile and motherboard. If a hacker steals your `vault.dat` file and your master password, they **still cannot unlock it** on another computer.

### 🥷 Active Malware Resistance
* **In-Memory Protection:** Passwords never sit idle in your computer's RAM in plain text. They are dynamically encrypted via DPAPI and only decrypted into RAM for the fraction of a second needed to view or copy them. This makes memory-dumping malware practically useless.
* **Anti-Screen Capture (Black Box Mode):** Utilizing low-level Windows APIs (`SetWindowDisplayAffinity`), MysticVault is physically invisible to screen recording software, Discord/Zoom screen-sharing, and background screenshot spyware.

### 🚀 Quality of Life & Convenience
* **Local Browser Extraction:** Built-in extraction engine that securely decrypts and imports your existing passwords directly from **Chrome, Edge, Brave**, and the **Zen Browser**.
* **System-Wide Auto-Lock:** Automatically locks your vault if you walk away from your PC and your system goes idle for 5 minutes (tracks global mouse/keyboard activity, not just the app window).
* **Self-Contained & Portable:** Entirely offline. Zero telemetry, zero cloud accounts, and zero internet connections. It can be built as a single standalone `.exe` file that requires no installation.

---

## 🛠️ How to Build

MysticVault is written cleanly and professionally with no bloated dependencies. 

To build it yourself, ensure you have the [.NET 8 SDK](https://dotnet.microsoft.com/) installed, then run:

```bash
# Clone the repository
git clone https://github.com/YourUsername/MysticVault.git
cd MysticVault

# Build the project
dotnet build -c Release
```

### 📦 Building a Standalone Executable
If you want to distribute MysticVault as a single, portable executable file that doesn't require users to install the .NET runtime, simply run:

```bash
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true
```

---

## 🔒 Security Disclaimer
MysticVault was designed to be highly resistant to common InfoStealers and malware. However, no software is 100% impenetrable. If a highly advanced rootkit achieves Ring-0 kernel access on your machine, it could theoretically log physical keystrokes before they reach the application. Always practice safe browsing habits!

---

*Open Source. Offline. Unbreakable.*
