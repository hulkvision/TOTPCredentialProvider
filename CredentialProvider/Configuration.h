/* TOTP Credential Provider
 * Configuration.h — Registry-based configuration
 *
 * Reads settings from HKCR\CLSID\{CLSID}\ registry key.
 *
 * Copyright 2026 — Apache License, Version 2.0
 */

#pragma once

#include <string>
#include <windows.h>
#include <credentialprovider.h>

class Configuration
{
public:
    // Registry path under HKEY_CLASSES_ROOT
    static const std::wstring registryPath;

    Configuration();

    void PrintConfiguration();

    // --- TOTP Settings ---
    int    totpDigits    = 6;       // Number of digits in OTP code
    int    totpPeriod    = 30;      // Time step in seconds
    int    totpWindow    = 1;       // Tolerance window (±N steps)
    std::wstring issuerName = L"Windows";  // Issuer in otpauth URI

    // --- Display text ---
    std::wstring loginText      = L"TOTP Login";
    std::wstring otpFieldText   = L"";
    std::wstring passFieldText  = L"";
    std::wstring usernameFieldText = L"";

    // --- Behavior ---
    std::wstring bitmapPath     = L"";
    std::wstring excludedAccount = L"";
    bool   releaseLog           = false;
    bool   noDefault            = false;

    // --- Runtime state (not from registry) ---
    bool   isSecondStep         = false;
    bool   isEnrollment         = false;
    bool   doAutoLogon          = false;
    bool   userCanceled         = false;
    bool   clearFields          = true;

    // --- Provider state ---
    struct PROVIDER
    {
        ICredentialProviderEvents* pCredentialProviderEvents = nullptr;
        UINT_PTR upAdviseContext = 0;

        CREDENTIAL_PROVIDER_USAGE_SCENARIO cpu = CPUS_INVALID;
        DWORD credPackFlags = 0;

        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr = nullptr;
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs = nullptr;
        PWSTR* status_text = nullptr;
        CREDENTIAL_PROVIDER_STATUS_ICON* status_icon = nullptr;
        ICredentialProviderCredentialEvents* pCredProvCredentialEvents = nullptr;
        ICredentialProviderCredential* pCredProvCredential = nullptr;
        wchar_t** field_strings = nullptr;
    } provider;

    // --- Credential state ---
    struct CREDENTIAL
    {
        std::wstring username = L"";
        std::wstring domain   = L"";
        std::wstring password = L"";
        std::wstring otp      = L"";
    } credential;

private:
    std::wstring ReadRegString(HKEY hRoot, const std::wstring& path, const std::wstring& name, const std::wstring& defaultVal);
    int ReadRegDword(HKEY hRoot, const std::wstring& path, const std::wstring& name, int defaultVal);
};
