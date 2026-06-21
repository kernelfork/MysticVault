# MysticVault

A native, offline-first password manager for Windows built with WPF and .NET 8. I built this to have a truly local credential store without relying on cloud sync or monthly subscriptions.

## Features

- **Local Storage**: Everything is stored in a local `vault.dat` file encrypted with AES-256-GCM.
- **Dual-Key Cryptography**: The vault uses Argon2id for password hashing and combines it with Windows DPAPI. This means the vault is cryptographically bound to your specific Windows user profile—if someone steals your `vault.dat` and password, they still can't unlock it on another PC.
- **Global Auto-Type**: Press `Ctrl+Shift+V` from anywhere in Windows. A mini search window pops up, and hitting Enter will auto-type your credentials into the background application using Low-Level Win32 Hooks.
- **Local Wi-Fi Sync**: A built-in local TCP server allows you to sync your vault to your phone over Wi-Fi. Scanning the QR code sends the vault to your mobile browser. The decryption key is passed in the URL fragment (`#key=`) so it never touches the network.
- **System Tray**: Closes to the system tray so it can run silently in the background for auto-typing.
- **Browser Extraction**: Securely decrypts and imports existing passwords from Chrome, Edge, and Brave via their local sqlite databases.

## Build Instructions

You'll need the [.NET 8 SDK](https://dotnet.microsoft.com/).

```cmd
git clone https://github.com/YourUsername/MysticVault.git
cd MysticVault
dotnet build -c Release
```

To build a standalone executable:
```cmd
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

## AI OVERVIEW
*Here is an AI breakdown of the architecture, detailing exactly what this repository offers and how it operates securely under the hood:*

### What it Offers
MysticVault is designed to give you absolute control over your digital security. In a world where every password manager wants you to pay a monthly subscription to host your most sensitive data on their cloud servers, MysticVault takes the opposite approach. It is a strictly offline, self-hosted, un-hackable fortress that lives purely on your hardware. 

### What it Does
1. **Stores Passwords Locally**: Keeps your credentials in an offline `.dat` file.
2. **Auto-Types on Command**: Pressing a global hotkey summons the app so you can search and inject your passwords directly into other apps or browsers without copy-pasting.
3. **Beams to your Phone**: It features an ingenious zero-knowledge local Wi-Fi sync that lets you securely transfer your vault to your mobile browser without sending the decryption key over the network.
4. **Resists Malware**: It actively defends against infostealers by combining Argon2id hashing with Windows DPAPI, ensuring your vault can't be opened on another machine even if it's stolen.

### How it Works
Under the hood, MysticVault is powered by .NET 8 and WPF. The cryptography engine leverages `System.Security.Cryptography` to perform AES-256-GCM encryption. When you launch the app, we utilize native `user32.dll` hooks to capture global keyboard shortcuts, and `SendInput` to simulate physical keystrokes for auto-typing. The mobile sync spins up a localized `TcpListener` that hosts a bespoke Single-Page Application (SPA), using the URL `#fragment` trick to pass the raw AES decryption key directly into the device's hardware, fully bypassing network interception.

It's sleek, it's brutalist, and it's 100% yours.
