/* TOTP Credential Provider — Setup.exe
 *
 * Unified installer and uninstaller for the TOTP Credential Provider.
 *
 * Usage:
 *   TOTPSetup.exe                  Interactive wizard
 *   TOTPSetup.exe /install         Silent install
 *   TOTPSetup.exe /uninstall       Silent uninstall
 *   TOTPSetup.exe /install /issuer "MyCompany" /excluded "DOMAIN\Admin"
 *
 * The DLL is embedded inside this EXE as a binary resource.
 * Only this single EXE file needs to be distributed.
 *
 * What it does:
 *   INSTALL:
 *     1. Copies TOTPCredentialProvider.dll → C:\Windows\System32\
 *     2. Registers COM CLSID under HKCR
 *     3. Registers as a Credential Provider under HKLM
 *     4. Writes configuration to registry
 *
 *   UNINSTALL:
 *     1. Removes Credential Provider registration
 *     2. Removes COM CLSID registration
 *     3. Deletes the DLL from System32
 *     4. Optionally removes all user secrets
 *
 * Copyright 2026 — Apache License, Version 2.0
 */

#include <windows.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <strsafe.h>
#include <string>
#include <vector>
#include <iostream>
#include <io.h>
#include <fcntl.h>
#include "setup_resource.h"

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
static const wchar_t* PROVIDER_CLSID   = L"{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}";
static const wchar_t* DLL_FILENAME     = L"TOTPCredentialProvider.dll";
static const wchar_t* PROVIDER_NAME    = L"TOTP Credential Provider";

static const wchar_t* REG_CP_PATH      = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}";
static const wchar_t* REG_CLSID_PATH   = L"SOFTWARE\\Classes\\CLSID\\{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}";
static const wchar_t* REG_INPROC_PATH  = L"SOFTWARE\\Classes\\CLSID\\{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}\\InprocServer32";
static const wchar_t* REG_SECRETS_PATH = L"SOFTWARE\\TOTPCredentialProvider";

// Filter DLL constants
static const wchar_t* FILTER_CLSID      = L"{B1C2D3E4-F5A6-4B7C-8D9E-0F1A2B3C4D5E}";
static const wchar_t* FILTER_DLL_FILENAME = L"TOTPCredentialProviderFilter.dll";
static const wchar_t* FILTER_NAME       = L"TOTP Credential Provider Filter";

static const wchar_t* REG_FILTER_PATH   = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Provider Filters\\{B1C2D3E4-F5A6-4B7C-8D9E-0F1A2B3C4D5E}";
static const wchar_t* REG_FILTER_CLSID  = L"SOFTWARE\\Classes\\CLSID\\{B1C2D3E4-F5A6-4B7C-8D9E-0F1A2B3C4D5E}";
static const wchar_t* REG_FILTER_INPROC = L"SOFTWARE\\Classes\\CLSID\\{B1C2D3E4-F5A6-4B7C-8D9E-0F1A2B3C4D5E}\\InprocServer32";

// ---------------------------------------------------------------------------
// Console helpers
// ---------------------------------------------------------------------------
namespace Console
{
    enum Color { WHITE = 7, GREEN = 10, RED = 12, YELLOW = 14, CYAN = 11, BRIGHT_WHITE = 15 };

    void SetColor(Color c)
    {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), static_cast<WORD>(c));
    }

    void PrintBanner()
    {
        SetColor(CYAN);
        std::wcout << L"\n";
        std::wcout << L"  +====================================================+\n";
        std::wcout << L"  |                                                    |\n";
        std::wcout << L"  |     TOTP Credential Provider Setup                 |\n";
        std::wcout << L"  |     Version 1.0.0                                  |\n";
        std::wcout << L"  |                                                    |\n";
        std::wcout << L"  +====================================================+\n";
        SetColor(WHITE);
        std::wcout << L"\n";
    }

    void PrintStep(const std::wstring& msg)
    {
        SetColor(CYAN);
        std::wcout << L"  [*] ";
        SetColor(WHITE);
        std::wcout << msg << std::endl;
    }

    void PrintOK(const std::wstring& msg)
    {
        SetColor(GREEN);
        std::wcout << L"  [✓] ";
        SetColor(WHITE);
        std::wcout << msg << std::endl;
    }

    void PrintError(const std::wstring& msg)
    {
        SetColor(RED);
        std::wcout << L"  [✗] ";
        SetColor(WHITE);
        std::wcout << msg << std::endl;
    }

    void PrintWarning(const std::wstring& msg)
    {
        SetColor(YELLOW);
        std::wcout << L"  [!] ";
        SetColor(WHITE);
        std::wcout << msg << std::endl;
    }

    void PrintInfo(const std::wstring& msg)
    {
        std::wcout << L"      " << msg << std::endl;
    }

    std::wstring Prompt(const std::wstring& question, const std::wstring& defaultVal)
    {
        SetColor(BRIGHT_WHITE);
        std::wcout << L"\n  " << question;
        if (!defaultVal.empty())
        {
            SetColor(CYAN);
            std::wcout << L" [" << defaultVal << L"]";
        }
        SetColor(WHITE);
        std::wcout << L": ";

        std::wstring input;
        std::getline(std::wcin, input);

        if (input.empty())
            return defaultVal;
        return input;
    }

    bool PromptYesNo(const std::wstring& question, bool defaultYes)
    {
        SetColor(BRIGHT_WHITE);
        std::wcout << L"\n  " << question;
        SetColor(CYAN);
        std::wcout << (defaultYes ? L" [Y/n]" : L" [y/N]");
        SetColor(WHITE);
        std::wcout << L": ";

        std::wstring input;
        std::getline(std::wcin, input);

        if (input.empty()) return defaultYes;
        return (input[0] == L'Y' || input[0] == L'y');
    }

    int PromptChoice(const std::wstring& question, const std::vector<std::wstring>& options, int defaultIdx)
    {
        SetColor(BRIGHT_WHITE);
        std::wcout << L"\n  " << question << L"\n";
        SetColor(WHITE);

        for (size_t i = 0; i < options.size(); i++)
        {
            std::wcout << L"    " << (i + 1) << L". " << options[i];
            if (static_cast<int>(i) == defaultIdx)
            {
                SetColor(CYAN);
                std::wcout << L" (default)";
                SetColor(WHITE);
            }
            std::wcout << L"\n";
        }

        std::wcout << L"  Choice: ";
        std::wstring input;
        std::getline(std::wcin, input);

        if (input.empty()) return defaultIdx;

        int choice = _wtoi(input.c_str()) - 1;
        if (choice >= 0 && choice < static_cast<int>(options.size()))
            return choice;
        return defaultIdx;
    }
}

// ---------------------------------------------------------------------------
// Admin check
// ---------------------------------------------------------------------------
bool IsRunAsAdmin()
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup))
    {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

bool RelaunchAsAdmin(int argc, wchar_t* argv[])
{
    // Build command line from argv
    std::wstring cmdLine;
    for (int i = 1; i < argc; i++)
    {
        if (i > 1) cmdLine += L" ";
        cmdLine += L"\"";
        cmdLine += argv[i];
        cmdLine += L"\"";
    }

    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas";
    sei.lpFile = exePath;
    sei.lpParameters = cmdLine.c_str();
    sei.nShow = SW_SHOWNORMAL;

    return ShellExecuteExW(&sei) != FALSE;
}

// ---------------------------------------------------------------------------
// File operations
// ---------------------------------------------------------------------------
std::wstring GetSystem32Path()
{
    wchar_t sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);
    return std::wstring(sysDir);
}

std::wstring GetExeDirectory()
{
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    PathRemoveFileSpecW(exePath);
    return std::wstring(exePath);
}

bool DLLExistsInSystem32()
{
    std::wstring path = GetSystem32Path() + L"\\" + DLL_FILENAME;
    return PathFileExistsW(path.c_str()) != FALSE;
}

// ---------------------------------------------------------------------------
// ExtractEmbeddedDLL - Extract a DLL from embedded resources to a target path
// ---------------------------------------------------------------------------
bool ExtractEmbeddedDLL(const std::wstring& targetPath, int resourceId)
{
    HMODULE hModule = GetModuleHandleW(nullptr);
    HRSRC hRes = FindResourceW(hModule, MAKEINTRESOURCEW(resourceId), RT_RCDATA);
    if (!hRes)
    {
        Console::PrintError(L"Embedded resource not found! (Resource ID: " + std::to_wstring(resourceId) + L")");
        return false;
    }

    HGLOBAL hData = LoadResource(hModule, hRes);
    if (!hData)
    {
        Console::PrintError(L"Failed to load embedded resource");
        return false;
    }

    void* pData = LockResource(hData);
    DWORD dwSize = SizeofResource(hModule, hRes);
    if (!pData || dwSize == 0)
    {
        Console::PrintError(L"Embedded resource is empty");
        return false;
    }

    // Write the resource data to the target file
    HANDLE hFile = CreateFileW(
        targetPath.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        Console::PrintError(L"Failed to create file: " + targetPath + L" (Error: " + std::to_wstring(err) + L")");
        if (err == ERROR_ACCESS_DENIED)
            Console::PrintInfo(L"The DLL may be in use. Try restarting and running again.");
        return false;
    }

    DWORD bytesWritten = 0;
    BOOL ok = WriteFile(hFile, pData, dwSize, &bytesWritten, nullptr);
    CloseHandle(hFile);

    if (!ok || bytesWritten != dwSize)
    {
        Console::PrintError(L"Failed to write DLL file (wrote " + std::to_wstring(bytesWritten) + L" of " + std::to_wstring(dwSize) + L" bytes)");
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// Registry operations
// ---------------------------------------------------------------------------
bool RegKeyExists(HKEY hRoot, const std::wstring& path)
{
    HKEY hKey;
    if (RegOpenKeyExW(hRoot, path.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

bool CreateRegKey(HKEY hRoot, const std::wstring& path, const std::wstring& defaultValue)
{
    HKEY hKey;
    DWORD disposition;
    LONG result = RegCreateKeyExW(hRoot, path.c_str(), 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, &disposition);

    if (result != ERROR_SUCCESS) return false;

    if (!defaultValue.empty())
    {
        RegSetValueExW(hKey, nullptr, 0, REG_SZ,
            reinterpret_cast<const BYTE*>(defaultValue.c_str()),
            static_cast<DWORD>((defaultValue.length() + 1) * sizeof(wchar_t)));
    }

    RegCloseKey(hKey);
    return true;
}

bool SetRegString(HKEY hRoot, const std::wstring& path,
    const std::wstring& name, const std::wstring& value)
{
    HKEY hKey;
    if (RegOpenKeyExW(hRoot, path.c_str(), 0, KEY_WRITE, &hKey) != ERROR_SUCCESS)
        return false;

    LONG result = RegSetValueExW(hKey, name.c_str(), 0, REG_SZ,
        reinterpret_cast<const BYTE*>(value.c_str()),
        static_cast<DWORD>((value.length() + 1) * sizeof(wchar_t)));

    RegCloseKey(hKey);
    return result == ERROR_SUCCESS;
}

bool SetRegDword(HKEY hRoot, const std::wstring& path,
    const std::wstring& name, DWORD value)
{
    HKEY hKey;
    if (RegOpenKeyExW(hRoot, path.c_str(), 0, KEY_WRITE, &hKey) != ERROR_SUCCESS)
        return false;

    LONG result = RegSetValueExW(hKey, name.c_str(), 0, REG_DWORD,
        reinterpret_cast<const BYTE*>(&value), sizeof(DWORD));

    RegCloseKey(hKey);
    return result == ERROR_SUCCESS;
}

bool DeleteRegTree(HKEY hRoot, const std::wstring& path)
{
    LONG result = RegDeleteTreeW(hRoot, path.c_str());
    return (result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Install configuration
// ---------------------------------------------------------------------------
struct InstallConfig
{
    std::wstring issuerName = L"Windows";
    std::wstring loginText = L"TOTP Login";
    std::wstring excludedAccount = L"";
    int totpDigits = 6;
    int totpPeriod = 30;
    int totpWindow = 1;
    bool enableLogging = false;
    bool silent = false;
};

// ---------------------------------------------------------------------------
// INSTALL
// ---------------------------------------------------------------------------
bool DoInstall(const InstallConfig& cfg)
{
    bool allOK = true;

    // Step 1: Extract embedded DLLs to System32
    Console::PrintStep(L"Extracting DLLs to System32...");
    {
        std::wstring dstPath = GetSystem32Path() + L"\\" + DLL_FILENAME;
        if (PathFileExistsW(dstPath.c_str()))
            Console::PrintWarning(L"Provider DLL already exists - overwriting...");

        if (ExtractEmbeddedDLL(dstPath, IDR_CREDENTIAL_PROVIDER_DLL))
            Console::PrintOK(L"Provider DLL extracted to " + dstPath);
        else
            allOK = false;

        std::wstring filterPath = GetSystem32Path() + L"\\" + FILTER_DLL_FILENAME;
        if (PathFileExistsW(filterPath.c_str()))
            Console::PrintWarning(L"Filter DLL already exists - overwriting...");

        if (ExtractEmbeddedDLL(filterPath, IDR_CREDENTIAL_PROVIDER_FILTER))
            Console::PrintOK(L"Filter DLL extracted to " + filterPath);
        else
            allOK = false;
    }

    // Step 2: Register COM CLSID for Provider
    Console::PrintStep(L"Registering COM classes...");
    {
        std::wstring dllFullPath = GetSystem32Path() + L"\\" + DLL_FILENAME;

        bool ok = true;
        ok &= CreateRegKey(HKEY_LOCAL_MACHINE, REG_CLSID_PATH, PROVIDER_NAME);
        ok &= CreateRegKey(HKEY_LOCAL_MACHINE, REG_INPROC_PATH, dllFullPath);
        if (ok)
        {
            SetRegString(HKEY_LOCAL_MACHINE, REG_INPROC_PATH, L"ThreadingModel", L"Apartment");
            Console::PrintOK(L"Provider COM class registered: " + std::wstring(PROVIDER_CLSID));
        }
        else
        {
            Console::PrintError(L"Failed to create Provider COM registry keys");
            allOK = false;
        }

        // Filter COM registration
        std::wstring filterFullPath = GetSystem32Path() + L"\\" + FILTER_DLL_FILENAME;
        ok = true;
        ok &= CreateRegKey(HKEY_LOCAL_MACHINE, REG_FILTER_CLSID, FILTER_NAME);
        ok &= CreateRegKey(HKEY_LOCAL_MACHINE, REG_FILTER_INPROC, filterFullPath);
        if (ok)
        {
            SetRegString(HKEY_LOCAL_MACHINE, REG_FILTER_INPROC, L"ThreadingModel", L"Apartment");
            Console::PrintOK(L"Filter COM class registered: " + std::wstring(FILTER_CLSID));
        }
        else
        {
            Console::PrintError(L"Failed to create Filter COM registry keys");
            allOK = false;
        }
    }

    // Step 3: Register as Credential Provider + Filter
    Console::PrintStep(L"Registering Credential Provider and Filter...");
    {
        if (CreateRegKey(HKEY_LOCAL_MACHINE, REG_CP_PATH, PROVIDER_NAME))
            Console::PrintOK(L"Credential Provider registered with Windows");
        else
        {
            Console::PrintError(L"Failed to register Credential Provider");
            allOK = false;
        }

        if (CreateRegKey(HKEY_LOCAL_MACHINE, REG_FILTER_PATH, FILTER_NAME))
            Console::PrintOK(L"Credential Provider Filter registered with Windows");
        else
        {
            Console::PrintError(L"Failed to register Credential Provider Filter");
            allOK = false;
        }
    }

    // Step 4: Write configuration
    Console::PrintStep(L"Writing configuration...");
    {
        SetRegString(HKEY_LOCAL_MACHINE, REG_CLSID_PATH, L"login_text", cfg.loginText);
        SetRegString(HKEY_LOCAL_MACHINE, REG_CLSID_PATH, L"issuer_name", cfg.issuerName);
        SetRegDword(HKEY_LOCAL_MACHINE, REG_CLSID_PATH, L"totp_digits", cfg.totpDigits);
        SetRegDword(HKEY_LOCAL_MACHINE, REG_CLSID_PATH, L"totp_period", cfg.totpPeriod);
        SetRegDword(HKEY_LOCAL_MACHINE, REG_CLSID_PATH, L"totp_window", cfg.totpWindow);
        SetRegDword(HKEY_LOCAL_MACHINE, REG_CLSID_PATH, L"release_log", cfg.enableLogging ? 1 : 0);

        if (!cfg.excludedAccount.empty())
            SetRegString(HKEY_LOCAL_MACHINE, REG_CLSID_PATH, L"excluded_account", cfg.excludedAccount);

        Console::PrintOK(L"Configuration written");
        Console::PrintInfo(L"  Issuer: " + cfg.issuerName);
        Console::PrintInfo(L"  Login text: " + cfg.loginText);
        Console::PrintInfo(L"  TOTP digits: " + std::to_wstring(cfg.totpDigits));
        Console::PrintInfo(L"  TOTP period: " + std::to_wstring(cfg.totpPeriod) + L"s");
        if (!cfg.excludedAccount.empty())
            Console::PrintInfo(L"  Excluded: " + cfg.excludedAccount);
        if (cfg.enableLogging)
            Console::PrintInfo(L"  Logging: ENABLED (C:\\totp-credential-provider.log)");
    }

    std::wcout << L"\n";
    if (allOK)
    {
        Console::SetColor(Console::GREEN);
        std::wcout << L"  ================================================\n";
        std::wcout << L"    Installation complete!\n";
        std::wcout << L"  ================================================\n";
        Console::SetColor(Console::WHITE);
        std::wcout << L"\n";
        Console::PrintInfo(L"Sign out or restart to activate TOTP login.");
        Console::PrintInfo(L"On first login, scan the QR code with your authenticator app.");
        std::wcout << L"\n";
        Console::PrintWarning(L"IMPORTANT: Keep this setup program available.");
        Console::PrintInfo(L"Run 'TOTPSetup.exe /uninstall' to remove the credential provider.");
    }
    else
    {
        Console::SetColor(Console::RED);
        std::wcout << L"  ══════════════════════════════════════════════\n";
        std::wcout << L"    Installation completed with errors!\n";
        std::wcout << L"  ══════════════════════════════════════════════\n";
        Console::SetColor(Console::WHITE);
    }

    return allOK;
}

// ---------------------------------------------------------------------------
// UNINSTALL
// ---------------------------------------------------------------------------
bool DoUninstall(bool removeSecrets, bool silent)
{
    bool allOK = true;

    // Step 1: Remove Credential Provider and Filter registration
    Console::PrintStep(L"Removing Credential Provider registration...");
    {
        if (DeleteRegTree(HKEY_LOCAL_MACHINE, REG_CP_PATH))
            Console::PrintOK(L"Credential Provider unregistered");
        else
            Console::PrintWarning(L"Credential Provider registration not found (already removed?)");

        if (DeleteRegTree(HKEY_LOCAL_MACHINE, REG_FILTER_PATH))
            Console::PrintOK(L"Credential Provider Filter unregistered");
        else
            Console::PrintWarning(L"Filter registration not found (already removed?)");
    }

    // Step 2: Remove COM CLSIDs
    Console::PrintStep(L"Removing COM class registrations...");
    {
        if (DeleteRegTree(HKEY_LOCAL_MACHINE, REG_CLSID_PATH))
            Console::PrintOK(L"Provider COM class unregistered");
        else
            Console::PrintWarning(L"Provider COM class registration not found");

        if (DeleteRegTree(HKEY_LOCAL_MACHINE, REG_FILTER_CLSID))
            Console::PrintOK(L"Filter COM class unregistered");
        else
            Console::PrintWarning(L"Filter COM class registration not found");
    }

    // Step 3: Delete DLLs from System32
    Console::PrintStep(L"Removing DLLs from System32...");
    {
        // Remove Provider DLL
        std::wstring dllPath = GetSystem32Path() + L"\\" + DLL_FILENAME;
        if (PathFileExistsW(dllPath.c_str()))
        {
            if (DeleteFileW(dllPath.c_str()))
                Console::PrintOK(L"Provider DLL deleted: " + dllPath);
            else
            {
                DWORD err = GetLastError();
                Console::PrintError(L"Failed to delete Provider DLL. Error: " + std::to_wstring(err));
                if (err == ERROR_ACCESS_DENIED)
                {
                    MoveFileExW(dllPath.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
                    Console::PrintOK(L"Provider DLL scheduled for deletion on next restart");
                }
                else
                    allOK = false;
            }
        }
        else
            Console::PrintWarning(L"Provider DLL not found in System32 (already removed?)");

        // Remove Filter DLL
        std::wstring filterPath = GetSystem32Path() + L"\\" + FILTER_DLL_FILENAME;
        if (PathFileExistsW(filterPath.c_str()))
        {
            if (DeleteFileW(filterPath.c_str()))
                Console::PrintOK(L"Filter DLL deleted: " + filterPath);
            else
            {
                DWORD err = GetLastError();
                Console::PrintError(L"Failed to delete Filter DLL. Error: " + std::to_wstring(err));
                if (err == ERROR_ACCESS_DENIED)
                {
                    MoveFileExW(filterPath.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
                    Console::PrintOK(L"Filter DLL scheduled for deletion on next restart");
                }
                else
                    allOK = false;
            }
        }
        else
            Console::PrintWarning(L"Filter DLL not found in System32 (already removed?)");
    }

    // Step 4: Optionally remove user secrets
    if (removeSecrets)
    {
        Console::PrintStep(L"Removing all user TOTP secrets...");
        if (DeleteRegTree(HKEY_LOCAL_MACHINE, REG_SECRETS_PATH))
            Console::PrintOK(L"All user secrets removed");
        else
            Console::PrintWarning(L"No user secrets found");
    }
    else
    {
        Console::PrintInfo(L"User TOTP secrets preserved (users will need to re-enroll if reinstalled).");
    }

    // Step 5: Clean up log file
    std::wstring logPath = L"C:\\totp-credential-provider.log";
    if (PathFileExistsW(logPath.c_str()))
    {
        Console::PrintStep(L"Removing log file...");
        if (DeleteFileW(logPath.c_str()))
            Console::PrintOK(L"Log file deleted");
        else
            Console::PrintWarning(L"Could not delete log file");
    }

    std::wcout << L"\n";
    if (allOK)
    {
        Console::SetColor(Console::GREEN);
        std::wcout << L"  ================================================\n";
        std::wcout << L"    Uninstallation complete!\n";
        std::wcout << L"  ================================================\n";
        Console::SetColor(Console::WHITE);
        std::wcout << L"\n";
        Console::PrintInfo(L"The standard Windows login will be restored after restart.");
    }
    else
    {
        Console::SetColor(Console::YELLOW);
        std::wcout << L"  ================================================\n";
        std::wcout << L"    Uninstallation completed with warnings.\n";
        std::wcout << L"    Restart to fully complete removal.\n";
        std::wcout << L"  ================================================\n";
        Console::SetColor(Console::WHITE);
    }

    return allOK;
}

// ---------------------------------------------------------------------------
// Interactive wizard
// ---------------------------------------------------------------------------
void RunInstallWizard()
{
    InstallConfig cfg;

    Console::SetColor(Console::BRIGHT_WHITE);
    std::wcout << L"  INSTALLATION WIZARD\n";
    Console::SetColor(Console::WHITE);
    std::wcout << L"  -----------------------------------------\n";

    // Verify embedded DLL resource exists
    {
        HRSRC hRes = FindResourceW(GetModuleHandleW(nullptr),
            MAKEINTRESOURCEW(IDR_CREDENTIAL_PROVIDER_DLL), RT_RCDATA);
        if (!hRes)
        {
            Console::PrintError(L"Embedded DLL resource not found in this EXE!");
            Console::PrintInfo(L"The setup EXE may be corrupt. Please re-download.");
            return;
        }
        DWORD size = SizeofResource(GetModuleHandleW(nullptr), hRes);
        Console::PrintOK(L"Embedded DLL verified (" + std::to_wstring(size / 1024) + L" KB)");
    }

    // Issuer name
    cfg.issuerName = Console::Prompt(L"Issuer name (shown in authenticator app)", L"Windows");

    // Login text
    cfg.loginText = Console::Prompt(L"Login tile text", L"TOTP Login");

    // Excluded account
    Console::PrintInfo(L"");
    Console::PrintInfo(L"You can exclude one account from TOTP (e.g., a recovery admin account).");
    cfg.excludedAccount = Console::Prompt(L"Excluded account (leave blank for none)", L"");

    // TOTP settings
    int digitChoice = Console::PromptChoice(L"OTP length:", { L"6 digits (recommended)", L"8 digits" }, 0);
    cfg.totpDigits = (digitChoice == 1) ? 8 : 6;

    cfg.totpPeriod = 30; // Keep simple

    // Logging
    cfg.enableLogging = Console::PromptYesNo(L"Enable debug logging?", false);

    // Confirm
    std::wcout << L"\n";
    Console::SetColor(Console::BRIGHT_WHITE);
    std::wcout << L"  CONFIGURATION SUMMARY\n";
    Console::SetColor(Console::WHITE);
    std::wcout << L"  -----------------------------------------\n";
    Console::PrintInfo(L"  Issuer:          " + cfg.issuerName);
    Console::PrintInfo(L"  Login text:      " + cfg.loginText);
    Console::PrintInfo(L"  OTP digits:      " + std::to_wstring(cfg.totpDigits));
    Console::PrintInfo(L"  OTP period:      " + std::to_wstring(cfg.totpPeriod) + L"s");
    if (!cfg.excludedAccount.empty())
        Console::PrintInfo(L"  Excluded:        " + cfg.excludedAccount);
    Console::PrintInfo(L"  Logging:         " + std::wstring(cfg.enableLogging ? L"ON" : L"OFF"));
    Console::PrintInfo(L"  DLL source:      Embedded in this EXE");
    Console::PrintInfo(L"  DLL destination: " + GetSystem32Path() + L"\\" + DLL_FILENAME);

    if (!Console::PromptYesNo(L"Proceed with installation?", true))
    {
        Console::PrintWarning(L"Installation cancelled.");
        return;
    }

    std::wcout << L"\n";
    DoInstall(cfg);
}

void RunUninstallWizard()
{
    Console::SetColor(Console::BRIGHT_WHITE);
    std::wcout << L"  UNINSTALLATION\n";
    Console::SetColor(Console::WHITE);
    std::wcout << L"  -----------------------------------------\n";

    bool isInstalled = DLLExistsInSystem32() ||
        RegKeyExists(HKEY_LOCAL_MACHINE, REG_CP_PATH);

    if (!isInstalled)
    {
        Console::PrintWarning(L"TOTP Credential Provider does not appear to be installed.");
        if (!Console::PromptYesNo(L"Continue with cleanup anyway?", false))
            return;
    }

    Console::PrintWarning(L"This will remove the TOTP Credential Provider from this computer.");
    Console::PrintInfo(L"The standard Windows login will be restored.");

    bool removeSecrets = Console::PromptYesNo(
        L"Also remove all stored TOTP secrets? (users will need to re-enroll)", false);

    if (!Console::PromptYesNo(L"Proceed with uninstallation?", true))
    {
        Console::PrintWarning(L"Uninstallation cancelled.");
        return;
    }

    std::wcout << L"\n";
    DoUninstall(removeSecrets, false);
}

// ---------------------------------------------------------------------------
// Command-line argument parsing
// ---------------------------------------------------------------------------
struct CmdArgs
{
    bool install = false;
    bool uninstall = false;
    bool silent = false;
    bool removeSecrets = false;
    bool help = false;
    InstallConfig config;
};

CmdArgs ParseArgs(int argc, wchar_t* argv[])
{
    CmdArgs args;

    for (int i = 1; i < argc; i++)
    {
        std::wstring arg = argv[i];

        // Normalize to lowercase for comparison
        for (auto& c : arg) c = towlower(c);

        if (arg == L"/install" || arg == L"-install" || arg == L"--install")
            args.install = true;
        else if (arg == L"/uninstall" || arg == L"-uninstall" || arg == L"--uninstall")
            args.uninstall = true;
        else if (arg == L"/silent" || arg == L"-silent" || arg == L"--silent" || arg == L"/s")
            args.silent = true;
        else if (arg == L"/removesecrets" || arg == L"-removesecrets")
            args.removeSecrets = true;
        else if (arg == L"/help" || arg == L"-help" || arg == L"--help" || arg == L"/?" || arg == L"-h")
            args.help = true;
        else if ((arg == L"/issuer" || arg == L"-issuer") && i + 1 < argc)
            args.config.issuerName = argv[++i];
        else if ((arg == L"/logintext" || arg == L"-logintext") && i + 1 < argc)
            args.config.loginText = argv[++i];
        else if ((arg == L"/excluded" || arg == L"-excluded") && i + 1 < argc)
            args.config.excludedAccount = argv[++i];
        else if ((arg == L"/digits" || arg == L"-digits") && i + 1 < argc)
            args.config.totpDigits = _wtoi(argv[++i]);
        else if (arg == L"/log" || arg == L"-log")
            args.config.enableLogging = true;
    }

    return args;
}

void PrintHelp()
{
    Console::PrintBanner();
    std::wcout << L"  Usage:\n";
    std::wcout << L"    TOTPSetup.exe                      Interactive wizard\n";
    std::wcout << L"    TOTPSetup.exe /install              Install with defaults\n";
    std::wcout << L"    TOTPSetup.exe /uninstall            Uninstall\n";
    std::wcout << L"\n";
    std::wcout << L"  Install options:\n";
    std::wcout << L"    /issuer \"Name\"          Issuer name for authenticator app\n";
    std::wcout << L"    /logintext \"Text\"       Login tile text\n";
    std::wcout << L"    /excluded \"DOMAIN\\User\" Account to skip 2FA\n";
    std::wcout << L"    /digits 6|8            OTP code length (default: 6)\n";
    std::wcout << L"    /log                   Enable debug logging\n";
    std::wcout << L"    /silent                No interactive prompts\n";
    std::wcout << L"\n";
    std::wcout << L"  Uninstall options:\n";
    std::wcout << L"    /removesecrets         Also delete all user TOTP secrets\n";
    std::wcout << L"    /silent                No interactive prompts\n";
    std::wcout << L"\n";
    std::wcout << L"  Examples:\n";
    std::wcout << L"    TOTPSetup.exe /install /issuer \"Contoso\" /excluded \"CONTOSO\\Admin\"\n";
    std::wcout << L"    TOTPSetup.exe /uninstall /removesecrets /silent\n";
    std::wcout << L"\n";
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int wmain(int argc, wchar_t* argv[])
{
    // Enable Unicode console output
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stdin), _O_U16TEXT);

    // Check admin
    if (!IsRunAsAdmin())
    {
        Console::PrintBanner();
        Console::PrintWarning(L"This program requires administrator privileges.");
        Console::PrintStep(L"Relaunching as administrator...");

        if (RelaunchAsAdmin(argc, argv))
            return 0;
        else
        {
            Console::PrintError(L"Failed to elevate. Please right-click and select 'Run as administrator'.");
            return 1;
        }
    }

    CmdArgs args = ParseArgs(argc, argv);

    if (args.help)
    {
        PrintHelp();
        return 0;
    }

    Console::PrintBanner();

    // Silent mode: install or uninstall directly
    if (args.install && args.silent)
    {
        return DoInstall(args.config) ? 0 : 1;
    }
    if (args.uninstall && args.silent)
    {
        return DoUninstall(args.removeSecrets, true) ? 0 : 1;
    }

    // Non-silent with explicit action
    if (args.install)
    {
        Console::PrintStep(L"Install mode selected via command line");
        std::wcout << L"\n";
        return DoInstall(args.config) ? 0 : 1;
    }
    if (args.uninstall)
    {
        Console::PrintStep(L"Uninstall mode selected via command line");
        std::wcout << L"\n";
        return DoUninstall(args.removeSecrets, false) ? 0 : 1;
    }

    // Interactive mode: ask what to do
    bool isInstalled = DLLExistsInSystem32() ||
        RegKeyExists(HKEY_LOCAL_MACHINE, REG_CP_PATH);

    if (isInstalled)
    {
        Console::PrintOK(L"TOTP Credential Provider is currently installed.");
        int choice = Console::PromptChoice(
            L"What would you like to do?",
            { L"Reinstall / Update", L"Uninstall", L"Exit" }, 0);

        std::wcout << L"\n";
        switch (choice)
        {
        case 0: RunInstallWizard(); break;
        case 1: RunUninstallWizard(); break;
        default: return 0;
        }
    }
    else
    {
        Console::PrintInfo(L"TOTP Credential Provider is not installed.");
        int choice = Console::PromptChoice(
            L"What would you like to do?",
            { L"Install", L"Exit" }, 0);

        std::wcout << L"\n";
        if (choice == 0)
            RunInstallWizard();
    }

    std::wcout << L"\n  Press Enter to exit...";
    std::wstring dummy;
    std::getline(std::wcin, dummy);

    return 0;
}
