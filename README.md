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
