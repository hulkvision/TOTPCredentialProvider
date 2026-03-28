/* TOTP Credential Provider
 * Configuration.cpp — Registry-based configuration implementation
 *
 * Copyright 2026 — Apache License, Version 2.0
 */

#include "Configuration.h"
#include "Logger.h"

using namespace std;

// Registry path: HKCR\CLSID\{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
const wstring Configuration::registryPath =
    L"CLSID\\{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}\\";

Configuration::Configuration()
{
    // Read TOTP settings
    totpDigits = ReadRegDword(HKEY_CLASSES_ROOT, registryPath, L"totp_digits", 6);
    totpPeriod = ReadRegDword(HKEY_CLASSES_ROOT, registryPath, L"totp_period", 30);
    totpWindow = ReadRegDword(HKEY_CLASSES_ROOT, registryPath, L"totp_window", 1);

    // Clamp values to sane ranges
    if (totpDigits < 6) totpDigits = 6;
    if (totpDigits > 8) totpDigits = 8;
    if (totpPeriod < 15) totpPeriod = 15;
    if (totpPeriod > 120) totpPeriod = 120;
    if (totpWindow < 0) totpWindow = 0;
    if (totpWindow > 5) totpWindow = 5;

    // Display text
    wstring tmp;
    tmp = ReadRegString(HKEY_CLASSES_ROOT, registryPath, L"login_text", L"");
    if (!tmp.empty()) loginText = tmp;

    tmp = ReadRegString(HKEY_CLASSES_ROOT, registryPath, L"issuer_name", L"");
    if (!tmp.empty()) issuerName = tmp;

    otpFieldText     = ReadRegString(HKEY_CLASSES_ROOT, registryPath, L"otp_text", L"");
    passFieldText    = ReadRegString(HKEY_CLASSES_ROOT, registryPath, L"password_text", L"");
    usernameFieldText = ReadRegString(HKEY_CLASSES_ROOT, registryPath, L"username_text", L"");

    // Behavior
    bitmapPath      = ReadRegString(HKEY_CLASSES_ROOT, registryPath, L"v1_bitmap_path", L"");
    excludedAccount = ReadRegString(HKEY_CLASSES_ROOT, registryPath, L"excluded_account", L"");
    releaseLog      = ReadRegDword(HKEY_CLASSES_ROOT, registryPath, L"release_log", 0) != 0;
    noDefault       = ReadRegDword(HKEY_CLASSES_ROOT, registryPath, L"no_default", 0) != 0;

    Logger::Get().enabled = releaseLog;
}

void Configuration::PrintConfiguration()
{
    DebugPrint("--- TOTP CP Configuration ---");
    DebugPrint(L"Login text: " + loginText);
    DebugPrint(L"Issuer: " + issuerName);
    DebugPrint(L"TOTP digits: " + to_wstring(totpDigits));
    DebugPrint(L"TOTP period: " + to_wstring(totpPeriod));
    DebugPrint(L"TOTP window: " + to_wstring(totpWindow));
    DebugPrint(L"Bitmap path: " + bitmapPath);
    DebugPrint(L"Excluded account: " + excludedAccount);
    DebugPrint(L"Release log: " + wstring(releaseLog ? L"true" : L"false"));
    DebugPrint("-----------------------------");
}

// ---------------------------------------------------------------------------
// Registry read helpers
// ---------------------------------------------------------------------------
wstring Configuration::ReadRegString(HKEY hRoot, const wstring& path,
    const wstring& name, const wstring& defaultVal)
{
    HKEY hKey;
    if (RegOpenKeyExW(hRoot, path.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return defaultVal;

    wchar_t buffer[1024] = { 0 };
    DWORD bufSize = sizeof(buffer);
    DWORD type = 0;

    LONG result = RegQueryValueExW(hKey, name.c_str(), nullptr, &type,
        reinterpret_cast<LPBYTE>(buffer), &bufSize);
    RegCloseKey(hKey);

    if (result == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ))
        return wstring(buffer);

    return defaultVal;
}

int Configuration::ReadRegDword(HKEY hRoot, const wstring& path,
    const wstring& name, int defaultVal)
{
    HKEY hKey;
    if (RegOpenKeyExW(hRoot, path.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return defaultVal;

    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    DWORD type = 0;

    LONG result = RegQueryValueExW(hKey, name.c_str(), nullptr, &type,
        reinterpret_cast<LPBYTE>(&value), &size);
    RegCloseKey(hKey);

    if (result == ERROR_SUCCESS && type == REG_DWORD)
        return static_cast<int>(value);

    return defaultVal;
}
