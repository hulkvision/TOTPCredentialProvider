# TOTP Credential Provider for Windows

A standalone Windows Credential Provider (V2) that adds TOTP-based two-factor authentication to Windows login, with self-service QR code enrollment.

## Features

- **TOTP-only authentication** — No server required, all validation done locally
- **Self-service enrollment** — QR code displayed on first login for authenticator app setup
- **Per-user secrets** — Each Windows user gets their own TOTP secret, stored encrypted via DPAPI
- **Supports any TOTP authenticator** — Google Authenticator, Microsoft Authenticator, Authy, etc.
- **Windows 10/11 and Server 2016+** support
- **No external dependencies** — Uses Windows BCrypt API for cryptography

## How It Works

### First Login (Enrollment)
1. User selects the TOTP Login tile
2. Enters Windows username and password → Submit
3. A QR code is displayed on screen
4. User scans the QR code with their authenticator app
5. User enters the 6-digit code from the app → Submit
6. TOTP secret is stored securely, login completes

### Subsequent Logins
1. User selects the TOTP Login tile
2. Enters Windows username and password → Submit
3. OTP input field appears
4. User enters the 6-digit code from their authenticator → Submit
5. Code is validated locally, login completes

## Building

### Prerequisites
- Visual Studio 2022 (or later) with C++ Desktop development workload
- Windows 10 SDK

### Build Steps
1. Open `TOTPCredentialProvider.sln` in Visual Studio
2. Select **Release | x64** configuration
3. Build → Build Solution
4. Output:
   - `TOTPCredentialProvider.dll` — The credential provider DLL
   - `TOTPSetup.exe` — The installer/uninstaller

## Installation

### Using TOTPSetup.exe (Recommended)

Place `TOTPSetup.exe` and `TOTPCredentialProvider.dll` in the same folder, then run:

**Interactive wizard:**
```cmd
TOTPSetup.exe
```
Walks you through configuration (issuer name, excluded account, OTP length, etc.)

**Silent install with defaults:**
```cmd
TOTPSetup.exe /install
```

**Silent install with custom settings:**
```cmd
TOTPSetup.exe /install /issuer "MyCompany" /excluded "DOMAIN\Admin" /digits 6 /log
```

### Manual Installation

1. Copy `TOTPCredentialProvider.dll` to `C:\Windows\System32\`
2. Run `Installer\register.reg` as Administrator
3. Sign out or restart

## Uninstallation

### Using TOTPSetup.exe (Recommended)

**Interactive:**
```cmd
TOTPSetup.exe /uninstall
```

**Silent (preserves user secrets):**
```cmd
TOTPSetup.exe /uninstall /silent
```

**Silent (removes everything including user secrets):**
```cmd
TOTPSetup.exe /uninstall /removesecrets /silent
```

### Manual Uninstallation

1. Run `Installer\unregister.reg` as Administrator
2. Delete `C:\Windows\System32\TOTPCredentialProvider.dll`
3. (Optional) Delete user secrets: `reg delete HKLM\SOFTWARE\TOTPCredentialProvider /f`

## TOTPSetup.exe Command Reference

| Flag | Description |
|---|---|
| `/install` | Install the credential provider |
| `/uninstall` | Uninstall the credential provider |
| `/silent` or `/s` | No interactive prompts |
| `/issuer "Name"` | Issuer name shown in authenticator app |
| `/logintext "Text"` | Login tile text |
| `/excluded "DOMAIN\User"` | Account to skip 2FA |
| `/digits 6\|8` | OTP code length |
| `/log` | Enable debug logging |
| `/removesecrets` | Also delete all user TOTP secrets (uninstall only) |
| `/help` | Show help |

## Configuration

Configuration is stored in the Windows Registry at:
```
HKEY_CLASSES_ROOT\CLSID\{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}\
```

| Registry Value | Type | Default | Description |
|---|---|---|---|
| `login_text` | REG_SZ | "TOTP Login" | Title text on the login tile |
| `issuer_name` | REG_SZ | "Windows" | Issuer name in the otpauth URI |
| `totp_digits` | REG_DWORD | 6 | Number of digits in OTP (6 or 8) |
| `totp_period` | REG_DWORD | 30 | Time step in seconds |
| `totp_window` | REG_DWORD | 1 | Tolerance window (±N steps) |
| `excluded_account` | REG_SZ | "" | Account to skip 2FA (e.g., `DOMAIN\Admin`) |
| `v1_bitmap_path` | REG_SZ | "" | Custom tile image path (128×128 BMP) |
| `release_log` | REG_DWORD | 0 | Enable debug logging |

## Admin Operations

### Reset a User's TOTP
Delete the user's registry key to force re-enrollment:
```cmd
reg delete "HKLM\SOFTWARE\TOTPCredentialProvider\Users\{USER-SID}" /f
```

### View Enrolled Users
```cmd
reg query "HKLM\SOFTWARE\TOTPCredentialProvider\Users"
```

### Enable Debug Logging
```cmd
reg add "HKCR\CLSID\{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}" /v release_log /t REG_DWORD /d 1 /f
```
Logs are written to `C:\totp-credential-provider.log`

## Security Notes

- TOTP secrets are encrypted using Windows DPAPI with machine scope
- Secrets are stored under `HKLM\SOFTWARE\TOTPCredentialProvider\Users\{SID}\`
- Only SYSTEM and Administrator accounts should have access to these keys
- For enterprise deployments with higher security requirements, consider a server-backed 2FA solution

## Architecture

```
TOTPCredentialProvider.dll (COM DLL)
├── Dll.cpp           — COM registration and class factory
├── CProvider.cpp     — ICredentialProvider (tile management)
├── CCredential.cpp   — Login flow (password → TOTP → Kerberos logon)
├── TOTPEngine.cpp    — RFC 6238 TOTP (HMAC-SHA1 via BCrypt)
├── QRCode.cpp        — Self-contained QR code generator
├── SecretStore.cpp   — DPAPI-encrypted per-user secret storage
├── Configuration.cpp — Registry-based settings
├── helpers.cpp       — Kerberos logon serialization
└── Logger.cpp        — Debug file logging
```

## License

Apache License, Version 2.0
