/* TOTP Credential Provider
 * SecretStore.cpp — DPAPI-encrypted per-user secret storage implementation
 *
 * Registry structure:
 *   HKLM\SOFTWARE\TOTPCredentialProvider\Users\{SID}\
 *     Secret    (REG_BINARY) — DPAPI-encrypted TOTP secret
 *     Enrolled  (REG_DWORD)  — 1 if enrollment completed
 *
 * Copyright 2026 — Apache License, Version 2.0
 */

#include "SecretStore.h"
#include "Logger.h"

#include <wincrypt.h>
#include <sddl.h>
#include <lmcons.h>
#include <security.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

const std::wstring SecretStore::registryBasePath =
    L"SOFTWARE\\TOTPCredentialProvider\\Users\\";

// ---------------------------------------------------------------------------
// GetUserKeyPath — Full registry path for a user SID
// ---------------------------------------------------------------------------
std::wstring SecretStore::GetUserKeyPath(const std::wstring& userSID)
{
    return registryBasePath + userSID;
}

// ---------------------------------------------------------------------------
// HasSecret — Check if a TOTP secret exists for the user
// ---------------------------------------------------------------------------
bool SecretStore::HasSecret(const std::wstring& userSID)
{
    if (userSID.empty()) return false;

    HKEY hKey;
    std::wstring path = GetUserKeyPath(userSID);

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;

    DWORD type = 0;
    DWORD size = 0;
    LONG result = RegQueryValueExW(hKey, L"Secret", nullptr, &type, nullptr, &size);
    RegCloseKey(hKey);

    return (result == ERROR_SUCCESS && type == REG_BINARY && size > 0);
}

// ---------------------------------------------------------------------------
// IsEnrolled — Check if the user has completed enrollment
// ---------------------------------------------------------------------------
bool SecretStore::IsEnrolled(const std::wstring& userSID)
{
    if (userSID.empty()) return false;

    HKEY hKey;
    std::wstring path = GetUserKeyPath(userSID);

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;

    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    DWORD type = 0;

    LONG result = RegQueryValueExW(hKey, L"Enrolled", nullptr, &type,
        reinterpret_cast<LPBYTE>(&value), &size);
    RegCloseKey(hKey);

    return (result == ERROR_SUCCESS && type == REG_DWORD && value == 1);
}

// ---------------------------------------------------------------------------
// GetSecret — Retrieve and decrypt the TOTP secret
// ---------------------------------------------------------------------------
std::vector<uint8_t> SecretStore::GetSecret(const std::wstring& userSID)
{
    if (userSID.empty()) return {};

    HKEY hKey;
    std::wstring path = GetUserKeyPath(userSID);

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
    {
        DebugPrint("SecretStore::GetSecret — Failed to open registry key");
        return {};
    }

    // First query to get the size
    DWORD type = 0;
    DWORD size = 0;
    if (RegQueryValueExW(hKey, L"Secret", nullptr, &type, nullptr, &size) != ERROR_SUCCESS ||
        type != REG_BINARY || size == 0)
    {
        RegCloseKey(hKey);
        DebugPrint("SecretStore::GetSecret — No secret found");
        return {};
    }

    // Read the encrypted data
    std::vector<uint8_t> encrypted(size);
    if (RegQueryValueExW(hKey, L"Secret", nullptr, nullptr,
        encrypted.data(), &size) != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        DebugPrint("SecretStore::GetSecret — Failed to read secret");
        return {};
    }
    RegCloseKey(hKey);

    // Decrypt with DPAPI
    return DecryptData(encrypted);
}

// ---------------------------------------------------------------------------
// StoreSecret — Encrypt and store a TOTP secret
// ---------------------------------------------------------------------------
HRESULT SecretStore::StoreSecret(const std::wstring& userSID,
    const std::vector<uint8_t>& secret)
{
    if (userSID.empty() || secret.empty()) return E_INVALIDARG;

    // Encrypt with DPAPI
    std::vector<uint8_t> encrypted = EncryptData(secret);
    if (encrypted.empty())
    {
        DebugPrint("SecretStore::StoreSecret — DPAPI encryption failed");
        return E_FAIL;
    }

    // Create/open registry key
    HKEY hKey;
    std::wstring path = GetUserKeyPath(userSID);
    DWORD disposition;

    LONG result = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        path.c_str(),
        0, nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        nullptr, // TODO: Set security descriptor to restrict access
        &hKey,
        &disposition);

    if (result != ERROR_SUCCESS)
    {
        DebugPrint("SecretStore::StoreSecret — Failed to create registry key");
        return HRESULT_FROM_WIN32(result);
    }

    // Write encrypted secret
    result = RegSetValueExW(hKey, L"Secret", 0, REG_BINARY,
        encrypted.data(), static_cast<DWORD>(encrypted.size()));

    if (result != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        DebugPrint("SecretStore::StoreSecret — Failed to write secret");
        return HRESULT_FROM_WIN32(result);
    }

    // Write enrollment time
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    DWORD64 enrollTime = uli.QuadPart;
    RegSetValueExW(hKey, L"EnrollmentTime", 0, REG_QWORD,
        reinterpret_cast<const BYTE*>(&enrollTime), sizeof(DWORD64));

    RegCloseKey(hKey);

    DebugPrint("SecretStore::StoreSecret — Secret stored successfully");
    return S_OK;
}

// ---------------------------------------------------------------------------
// MarkEnrolled — Set the enrolled flag
// ---------------------------------------------------------------------------
HRESULT SecretStore::MarkEnrolled(const std::wstring& userSID)
{
    if (userSID.empty()) return E_INVALIDARG;

    HKEY hKey;
    std::wstring path = GetUserKeyPath(userSID);

    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_WRITE, &hKey);
    if (result != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(result);

    DWORD enrolled = 1;
    result = RegSetValueExW(hKey, L"Enrolled", 0, REG_DWORD,
        reinterpret_cast<const BYTE*>(&enrolled), sizeof(DWORD));
    RegCloseKey(hKey);

    if (result == ERROR_SUCCESS)
        DebugPrint("SecretStore::MarkEnrolled — User marked as enrolled");

    return HRESULT_FROM_WIN32(result);
}

// ---------------------------------------------------------------------------
// DeleteSecret — Remove a user's TOTP data (admin reset)
// ---------------------------------------------------------------------------
HRESULT SecretStore::DeleteSecret(const std::wstring& userSID)
{
    if (userSID.empty()) return E_INVALIDARG;

    std::wstring path = GetUserKeyPath(userSID);
    LONG result = RegDeleteTreeW(HKEY_LOCAL_MACHINE, path.c_str());

    if (result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND)
    {
        DebugPrint("SecretStore::DeleteSecret — User secret deleted");
        return S_OK;
    }

    return HRESULT_FROM_WIN32(result);
}

// ---------------------------------------------------------------------------
// GetUserSID — Resolve username to SID string
// ---------------------------------------------------------------------------
std::wstring SecretStore::GetUserSID(const std::wstring& username)
{
    if (username.empty()) return L"";

    DWORD sidSize = 0;
    DWORD domainSize = 0;
    SID_NAME_USE sidType;

    // First call to get sizes
    LookupAccountNameW(nullptr, username.c_str(), nullptr, &sidSize,
        nullptr, &domainSize, &sidType);

    if (sidSize == 0) return L"";

    std::vector<BYTE> sidBuffer(sidSize);
    std::vector<wchar_t> domainBuffer(domainSize);

    if (!LookupAccountNameW(nullptr, username.c_str(),
        sidBuffer.data(), &sidSize,
        domainBuffer.data(), &domainSize, &sidType))
    {
        DebugPrint("SecretStore::GetUserSID — LookupAccountName failed");
        return L"";
    }

    LPWSTR sidString = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<PSID>(sidBuffer.data()), &sidString))
    {
        DebugPrint("SecretStore::GetUserSID — ConvertSidToStringSid failed");
        return L"";
    }

    std::wstring result(sidString);
    LocalFree(sidString);
    return result;
}

// ---------------------------------------------------------------------------
// DPAPI Encryption
// ---------------------------------------------------------------------------
std::vector<uint8_t> SecretStore::EncryptData(const std::vector<uint8_t>& plaintext)
{
    DATA_BLOB input;
    input.pbData = const_cast<BYTE*>(plaintext.data());
    input.cbData = static_cast<DWORD>(plaintext.size());

    DATA_BLOB output = { 0 };

    // Encrypt with DPAPI — CRYPTPROTECT_LOCAL_MACHINE makes it machine-scope
    // (decryptable by any user/process on this machine running as SYSTEM)
    if (!CryptProtectData(
        &input,
        L"TOTP Secret",     // Description
        nullptr,            // Optional entropy
        nullptr,            // Reserved
        nullptr,            // Prompt struct
        CRYPTPROTECT_LOCAL_MACHINE, // Machine scope
        &output))
    {
        DebugPrint("SecretStore::EncryptData — CryptProtectData failed");
        return {};
    }

    std::vector<uint8_t> result(output.pbData, output.pbData + output.cbData);
    LocalFree(output.pbData);
    return result;
}

// ---------------------------------------------------------------------------
// DPAPI Decryption
// ---------------------------------------------------------------------------
std::vector<uint8_t> SecretStore::DecryptData(const std::vector<uint8_t>& ciphertext)
{
    DATA_BLOB input;
    input.pbData = const_cast<BYTE*>(ciphertext.data());
    input.cbData = static_cast<DWORD>(ciphertext.size());

    DATA_BLOB output = { 0 };

    if (!CryptUnprotectData(
        &input,
        nullptr,            // Description out
        nullptr,            // Optional entropy
        nullptr,            // Reserved
        nullptr,            // Prompt struct
        CRYPTPROTECT_LOCAL_MACHINE,
        &output))
    {
        DebugPrint("SecretStore::DecryptData — CryptUnprotectData failed");
        return {};
    }

    std::vector<uint8_t> result(output.pbData, output.pbData + output.cbData);
    // Secure zero the DPAPI output before freeing
    SecureZeroMemory(output.pbData, output.cbData);
    LocalFree(output.pbData);
    return result;
}
