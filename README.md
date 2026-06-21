# MysticVault

A desktop-native, strictly offline password manager for Windows built with WPF and .NET 8. I built this to have a truly local credential store without relying on cloud sync or monthly subscriptions.

## Features

- **Local Storage**: Everything is stored in a local `vault.dat` file encrypted with AES-256-GCM.
- **Dual-Key Cryptography**: The vault uses Argon2id for password hashing and combines it with Windows DPAPI. This means the vault is cryptographically bound to your specific Windows user profile—if someone steals your `vault.dat` and password, they still can't unlock it on another PC.
- **Global Auto-Type**: Press `Ctrl+Shift+V` from anywhere in Windows. A mini search window pops up, and hitting Enter will auto-type your credentials into the background application using Low-Level Win32 Hooks.
- **Local Wi-Fi Sync**: A built-in local TCP server allows you to sync your vault to your phone over Wi-Fi. Scanning the QR code sends the vault to your mobile browser. The decryption key is embedded directly in the served HTML as a JavaScript constant so QR-scanning apps (which strip URL fragments) still see it.
- **System Tray**: Closes to the system tray so it can run silently in the background for auto-typing.
- **Browser Extraction**: Securely decrypts and imports existing passwords from Chrome, Edge, and Brave via their local sqlite databases.

## Build Instructions

You'll need the [.NET 8 SDK](https://dotnet.microsoft.com/).

```cmd
git clone https://github.com/kernelfork/MysticVault.git
cd MysticVault
dotnet build -c Release
```

To build a standalone executable:
```cmd
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

## Overview
*Here is a breakdown of the architecture, detailing exactly what this repository offers and how it operates securely under the hood:*

### What it Offers
MysticVault is designed to give you absolute control over your digital security. In a world where every password manager wants you to pay a monthly subscription to host your most sensitive data on their cloud servers, MysticVault takes the opposite approach. It is a strictly offline, self-hosted, un-hackable fortress that lives purely on your hardware. 

### What it Does
1. **Stores Passwords Locally**: Keeps your credentials in an offline `.dat` file.
2. **Auto-Types on Command**: Pressing a global hotkey summons the app so you can search and inject your passwords directly into other apps or browsers without copy-pasting.
3. **Beams to your Phone**: It features an ingenious zero-knowledge local Wi-Fi sync that lets you securely transfer your vault to your mobile browser without sending the decryption key over the network.
4. **Resists Malware**: It actively defends against infostealers by combining Argon2id hashing with Windows DPAPI, ensuring your vault can't be opened on another machine even if it's stolen.
5. **Anti-Screenshot Protection**: The app window is mathematically blacked out from the OS. It is physically invisible to screen recording software, background screenshot spyware, and screen-sharing tools.
6. **Bypasses Keyloggers**: By utilizing low-level simulated keystrokes for auto-typing, it completely bypasses the Windows clipboard. Your passwords are injected directly into target applications, rendering clipboard-monitoring malware blind.
7. **Runs Invisibly**: It can be minimized directly to your Windows System Tray, allowing the global hotkey listener to stay active indefinitely without cluttering your taskbar.
8. **Secure Browser Import**: It can securely decrypt and import your existing passwords directly from the local encrypted databases of Chrome, Edge, Brave, and Zen Browser without ever needing a vulnerable plaintext CSV export.
9. **Idle Auto-Lock**: It monitors your global system activity and will automatically seal the vault if you step away from your computer for 5 minutes.

### How it Works
Under the hood, MysticVault is powered by .NET 8 and WPF. The cryptography engine leverages `System.Security.Cryptography` to perform AES-256-GCM encryption. When you launch the app, I utilize native `user32.dll` hooks to capture global keyboard shortcuts, and `SendInput` to simulate physical keystrokes for auto-typing. The mobile sync spins up a localized `TcpListener` that hosts a bespoke Single-Page Application (SPA). The ephemeral decryption key is embedded in the served HTML as a JavaScript constant (`B64_KEY`), and the client decrypts entries entirely in-browser using pure-JS SHA-256 keystream XOR + HMAC-SHA256 — no `window.crypto.subtle` dependency, no third-party library, works over plain HTTP on any browser.

## Advanced
Because standard cryptography isn't enough, I engineered three aggressive defense mechanisms into the core engine to defend against memory-dumping and reverse-engineering:
1. **In-Memory Master Key Protection**: Unlike standard password managers that leave your decrypted master key sitting in RAM, MysticVault uses native DPAPI `CryptProtectMemory` (`crypt32.dll`) to keep the key actively encrypted in the system memory. It is only decrypted for the exact microsecond an encryption event occurs, and then instantly mathematically scrambled again.
2. **Extreme Key Derivation**: I don't just use Argon2id—I cranked the OWASP parameters to the extreme. Unlocking the vault requires **10 iterations** across **256 Megabytes** of RAM, designed explicitly to physically exhaust ASICs and future quantum brute-forcing.
3. **Aggressive Anti-Debugging**: The application has an embedded background thread that constantly polls `kernel32.dll` for `IsDebuggerPresent()` and `CheckRemoteDebuggerPresent()`. If malware, an infostealer, or a reverse-engineer attempts to attach a debugger to dump the application's memory, MysticVault instantly self-destructs the process to protect the vault.
4. **Hardware-Binding (DPAPI Enforced)**: The `vault.dat` file is unconditionally wrapped in `ProtectedData` bound to your specific Windows User Profile. Even if a threat actor steals your vault file and knows the master password, it is mathematically impossible to decrypt it on any other machine. 
5. **Anti-DLL Injection**: I utilize `SetProcessMitigationPolicy` to interact directly with the Windows Kernel, explicitly blocking any non-Microsoft signed DLLs from injecting into the process space, rendering generic infostealers useless.
6. **Double-Integrity Verification**: On top of the standard AES-GCM Authentication Tag, the entire encrypted payload is explicitly re-signed using an `HMAC-SHA256` signature to mathematically prove zero tampering before memory parsing occurs.

It's sleek, it's brutalist, and it's 100% yours.
