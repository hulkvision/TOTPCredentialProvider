/* TOTP Credential Provider
 * CCredential.cpp — Credential tile implementation
 *
 * This is the core login flow:
 *
 * FIRST LOGIN (no TOTP secret stored):
 *   1. User enters username + password → Submit
 *   2. Connect() detects no TOTP secret → generates secret + QR code
 *   3. GetSerialization() shows enrollment screen (QR + OTP input)
 *   4. User scans QR, enters OTP → Submit
 *   5. Connect() validates OTP → stores secret → marks enrolled
 *   6. GetSerialization() packs Kerberos credentials → login
 *
 * SUBSEQUENT LOGINS (TOTP secret exists):
 *   1. User enters username + password → Submit
 *   2. GetSerialization() shows OTP screen
 *   3. User enters OTP → Submit
 *   4. Connect() validates OTP against stored secret
 *   5. GetSerialization() packs Kerberos credentials → login
 *
 * Copyright 2026 — Apache License, Version 2.0
 */

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif

#include "CCredential.h"
#include "Logger.h"
#include "resource.h"
#include "guid.h"

#include <string>
#include <algorithm>
#include <thread>
#include <sddl.h>

#pragma comment(lib, "wtsapi32.lib")

using namespace std;

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------
CCredential::CCredential(std::shared_ptr<Configuration> c) :
    _config(c), _authSuccess(false), _hQRBitmap(nullptr)
{
    _cRef = 1;
    _pCredProvCredentialEvents = nullptr;

    DllAddRef();

    ZERO(_rgCredProvFieldDescriptors);
    ZERO(_rgFieldStatePairs);
    ZERO(_rgFieldStrings);
}

CCredential::~CCredential()
{
    // Clean up field strings
    for (int i = 0; i < FID_NUM_FIELDS; i++)
    {
        if (_rgFieldStrings[i])
        {
            CoTaskMemFree(_rgFieldStrings[i]);
            _rgFieldStrings[i] = nullptr;
        }
    }

    // Clean up QR bitmap
    if (_hQRBitmap)
    {
        DeleteObject(_hQRBitmap);
        _hQRBitmap = nullptr;
    }

    // Secure zero enrollment secret
    if (!_enrollmentSecret.empty())
    {
        SecureZeroMemory(_enrollmentSecret.data(), _enrollmentSecret.size());
        _enrollmentSecret.clear();
    }

    DllRelease();
}

// ---------------------------------------------------------------------------
// Initialize — Set up fields from provider
// ---------------------------------------------------------------------------
HRESULT CCredential::Initialize(
    __in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
    __in const FIELD_STATE_PAIR* rgfsp,
    __in_opt PWSTR user_name,
    __in_opt PWSTR domain_name,
    __in_opt PWSTR password)
{
    DebugPrint(__FUNCTION__);
    HRESULT hr = S_OK;

    const FIELD_STATE_PAIR* initialFsp = rgfsp;

    if (NOT_EMPTY(user_name))
        _config->credential.username = wstring(user_name);
    if (NOT_EMPTY(domain_name))
        _config->credential.domain = wstring(domain_name);

    if (NOT_EMPTY(password))
    {
        _config->credential.password = wstring(password);
        SecureZeroMemory(password, wcslen(password) * sizeof(wchar_t));

        // We already have the password (from RDP/NLA), so skip the first step!
        wstring cleanUser = GetCleanUsername();
        wstring userSID = SecretStore::GetUserSID(cleanUser);

        if (!userSID.empty() && SecretStore::IsEnrolled(userSID))
        {
            DebugPrint("RDP Login: User enrolled — starting directly in OTP step");
            _config->isSecondStep = true;
            _config->isEnrollment = false;
            initialFsp = s_rgScenarioOTPStep;
        }
        else
        {
            DebugPrint("RDP Login: User not enrolled — starting directly in Enrollment step");
            _config->isEnrollment = true;
            _config->isSecondStep = false;
            initialFsp = s_rgScenarioEnrollment;

            // Generate TOTP secret immediately
            _enrollmentSecret = TOTPEngine::GenerateSecret(20);
            _enrollmentBase32 = TOTPEngine::Base32Encode(_enrollmentSecret);

            string usernameUTF8 = TOTPEngine::WideToUTF8(cleanUser);
            string issuerUTF8 = TOTPEngine::WideToUTF8(_config->issuerName);
            string otpauthURI = TOTPEngine::BuildOTPAuthURI(
                _enrollmentBase32, usernameUTF8, issuerUTF8,
                _config->totpDigits, _config->totpPeriod);

            if (_hQRBitmap) DeleteObject(_hQRBitmap);
            _hQRBitmap = QRCode::GenerateBitmap(otpauthURI, 4);
        }
    }

    for (DWORD i = 0; SUCCEEDED(hr) && i < FID_NUM_FIELDS; i++)
    {
        _rgFieldStatePairs[i] = initialFsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
        if (FAILED(hr)) break;

        // Initialize string values
        switch (i)
        {
        case FID_LARGE_TEXT:
            if (_config->isEnrollment)
                hr = SHStrDupW(L"Set Up Authenticator", &_rgFieldStrings[i]);
            else
                hr = SHStrDupW(_config->loginText.c_str(), &_rgFieldStrings[i]);
            break;
        case FID_SMALL_TEXT:
            if (_config->isEnrollment)
            {
                wstring hint = L"Scan the QR code, or enter this manual key:\n" +
                               TOTPEngine::UTF8ToWide(_enrollmentBase32) + 
                               L"\n\nThen enter the 6-digit code below.";
                hr = SHStrDupW(hint.c_str(), &_rgFieldStrings[i]);
            }
            else if (_config->isSecondStep)
            {
                hr = SHStrDupW(L"Enter the code from your authenticator app.", &_rgFieldStrings[i]);
            }
            else
            {
                hr = SHStrDupW(L"", &_rgFieldStrings[i]);
            }
            break;
        case FID_USERNAME:
            hr = SHStrDupW(_config->credential.username.c_str(), &_rgFieldStrings[i]);
            break;
        default:
            hr = SHStrDupW(L"", &_rgFieldStrings[i]);
            break;
        }
    }

    return hr;
}

// ---------------------------------------------------------------------------
// Advise / UnAdvise
// ---------------------------------------------------------------------------
HRESULT CCredential::Advise(__in ICredentialProviderCredentialEvents* pcpce)
{
    if (_pCredProvCredentialEvents)
        _pCredProvCredentialEvents->Release();
    _pCredProvCredentialEvents = pcpce;
    _pCredProvCredentialEvents->AddRef();
    return S_OK;
}

HRESULT CCredential::UnAdvise()
{
    if (_pCredProvCredentialEvents)
        _pCredProvCredentialEvents->Release();
    _pCredProvCredentialEvents = nullptr;
    return S_OK;
}

// ---------------------------------------------------------------------------
// SetSelected / SetDeselected
// ---------------------------------------------------------------------------
HRESULT CCredential::SetSelected(__out BOOL* pbAutoLogon)
{
    DebugPrint(__FUNCTION__);
    *pbAutoLogon = FALSE;

    if (_config->doAutoLogon)
    {
        *pbAutoLogon = TRUE;
        _config->doAutoLogon = false;
    }

    return S_OK;
}

HRESULT CCredential::SetDeselected()
{
    DebugPrint(__FUNCTION__);

    // Clear sensitive fields
    for (int i = 0; i < FID_NUM_FIELDS; i++)
    {
        if (_rgCredProvFieldDescriptors[i].cpft == CPFT_PASSWORD_TEXT ||
            _rgCredProvFieldDescriptors[i].cpft == CPFT_EDIT_TEXT)
        {
            if (_rgFieldStrings[i])
            {
                size_t len = wcslen(_rgFieldStrings[i]);
                SecureZeroMemory(_rgFieldStrings[i], len * sizeof(wchar_t));
            }
            if (_pCredProvCredentialEvents)
                _pCredProvCredentialEvents->SetFieldString(this, i, L"");
        }
    }

    // Reset state
    _config->isSecondStep = false;
    _config->isEnrollment = false;
    _authSuccess = false;

    return S_OK;
}

// ---------------------------------------------------------------------------
// GetFieldState / GetStringValue / GetBitmapValue
// ---------------------------------------------------------------------------
HRESULT CCredential::GetFieldState(
    __in DWORD dwFieldID,
    __out CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
    __out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
{
    if (dwFieldID < FID_NUM_FIELDS && pcpfs && pcpfis)
    {
        *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
        return S_OK;
    }
    return E_INVALIDARG;
}

HRESULT CCredential::GetStringValue(
    __in DWORD dwFieldID,
    __deref_out PWSTR* ppwsz)
{
    if (dwFieldID < FID_NUM_FIELDS && ppwsz)
        return SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
    return E_INVALIDARG;
}

HRESULT CCredential::GetBitmapValue(
    __in DWORD dwFieldID,
    __out HBITMAP* phbmp)
{
    DebugPrint(__FUNCTION__);
    HRESULT hr = E_INVALIDARG;

    if (dwFieldID == FID_LOGO && phbmp)
    {
        // During enrollment, show QR code as the tile image
        if (_config->isEnrollment && _hQRBitmap)
        {
            // LogonUI takes ownership and calls DeleteObject on the returned HBITMAP.
            // We must give it a COPY so we don't lose our cached QR code!
            *phbmp = (HBITMAP)CopyImage(_hQRBitmap, IMAGE_BITMAP, 0, 0, LR_CREATEDIBSECTION);
            hr = S_OK;
        }
        else
        {
            // Load custom bitmap or default tile
            HBITMAP hbmp = nullptr;
            if (!_config->bitmapPath.empty())
            {
                DWORD attrib = GetFileAttributesW(_config->bitmapPath.c_str());
                if (attrib != INVALID_FILE_ATTRIBUTES)
                {
                    hbmp = (HBITMAP)LoadImageW(nullptr, _config->bitmapPath.c_str(),
                        IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE);
                }
            }
            if (!hbmp)
                hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));

            if (hbmp)
            {
                *phbmp = hbmp;
                hr = S_OK;
            }
            else
            {
                hr = HRESULT_FROM_WIN32(GetLastError());
            }
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

HRESULT CCredential::GetSubmitButtonValue(
    __in DWORD dwFieldID,
    __out DWORD* pdwAdjacentTo)
{
    if (FID_SUBMIT_BUTTON == dwFieldID && pdwAdjacentTo)
    {
        // Place submit button next to OTP field if in OTP/enrollment step,
        // otherwise next to password field
        if (_config->isSecondStep || _config->isEnrollment)
            *pdwAdjacentTo = FID_OTP;
        else
            *pdwAdjacentTo = FID_LDAP_PASS;
        return S_OK;
    }
    return E_INVALIDARG;
}

// ---------------------------------------------------------------------------
// SetStringValue — Called on each keystroke
// ---------------------------------------------------------------------------
HRESULT CCredential::SetStringValue(
    __in DWORD dwFieldID,
    __in PCWSTR pwz)
{
    if (dwFieldID < FID_NUM_FIELDS &&
        (_rgCredProvFieldDescriptors[dwFieldID].cpft == CPFT_EDIT_TEXT ||
         _rgCredProvFieldDescriptors[dwFieldID].cpft == CPFT_PASSWORD_TEXT))
    {
        PWSTR* ppwszStored = &_rgFieldStrings[dwFieldID];
        CoTaskMemFree(*ppwszStored);
        return SHStrDupW(pwz, ppwszStored);
    }
    return E_INVALIDARG;
}

// Unused control handlers
HRESULT CCredential::GetCheckboxValue(DWORD, BOOL* pb, PWSTR* pp) { *pb = FALSE; return S_OK; }
HRESULT CCredential::GetComboBoxValueCount(DWORD, DWORD* pc, DWORD* pd) { *pc = 0; *pd = 0; return E_INVALIDARG; }
HRESULT CCredential::GetComboBoxValueAt(DWORD, DWORD, PWSTR*) { return E_INVALIDARG; }
HRESULT CCredential::SetCheckboxValue(DWORD, BOOL) { return S_OK; }
HRESULT CCredential::SetComboBoxSelectedValue(DWORD, DWORD) { return E_INVALIDARG; }
HRESULT CCredential::CommandLinkClicked(DWORD) { return E_INVALIDARG; }

// ---------------------------------------------------------------------------
// ReadFieldValues — Copy field string values into config
// ---------------------------------------------------------------------------
void CCredential::ReadFieldValues()
{
    if (_rgFieldStrings[FID_USERNAME] && wcslen(_rgFieldStrings[FID_USERNAME]) > 0)
        _config->credential.username = _rgFieldStrings[FID_USERNAME];

    if (_rgFieldStrings[FID_LDAP_PASS] && wcslen(_rgFieldStrings[FID_LDAP_PASS]) > 0)
        _config->credential.password = _rgFieldStrings[FID_LDAP_PASS];

    if (_rgFieldStrings[FID_OTP] && wcslen(_rgFieldStrings[FID_OTP]) > 0)
        _config->credential.otp = _rgFieldStrings[FID_OTP];
}

// ---------------------------------------------------------------------------
// GetCleanUsername — Strip domain prefix if present
// ---------------------------------------------------------------------------
wstring CCredential::GetCleanUsername()
{
    wstring clean = _config->credential.username;

    // Remove domain\ prefix
    size_t pos = clean.find(L'\\');
    if (pos != wstring::npos)
        clean = clean.substr(pos + 1);

    // Remove @domain suffix
    pos = clean.find(L'@');
    if (pos != wstring::npos)
        clean = clean.substr(0, pos);

    return clean;
}

// ---------------------------------------------------------------------------
// SetScenario — Switch the UI to a different scenario
// ---------------------------------------------------------------------------
void CCredential::SetScenario(TOTP_SCENARIO scenario)
{
    const FIELD_STATE_PAIR* fsp = nullptr;

    switch (scenario)
    {
    case TOTP_SCENARIO::LOGON_PASSWORD_FIRST:
        fsp = s_rgScenarioLogonPasswordFirst;
        break;
    case TOTP_SCENARIO::UNLOCK_PASSWORD:
        fsp = s_rgScenarioUnlockPassword;
        break;
    case TOTP_SCENARIO::OTP_STEP:
        fsp = s_rgScenarioOTPStep;
        break;
    case TOTP_SCENARIO::ENROLLMENT:
        fsp = s_rgScenarioEnrollment;
        break;
    default:
        return;
    }

    SetFieldStatePairBatch(fsp);
}

void CCredential::SetFieldStatePairBatch(const FIELD_STATE_PAIR* pFSP)
{
    if (!_pCredProvCredentialEvents) return;

    for (DWORD i = 0; i < FID_NUM_FIELDS; i++)
    {
        _pCredProvCredentialEvents->SetFieldState(this, i, pFSP[i].cpfs);
        _pCredProvCredentialEvents->SetFieldInteractiveState(this, i, pFSP[i].cpfis);
    }
}

void CCredential::ShowErrorMessage(const std::wstring& message)
{
    if (_config->provider.status_icon)
        *_config->provider.status_icon = CPSI_ERROR;
    if (_config->provider.status_text)
        SHStrDupW(message.c_str(), _config->provider.status_text);
}

// ---------------------------------------------------------------------------
// Connect — Called BEFORE GetSerialization when submit is pressed.
//           This is where we do OTP validation.
// ---------------------------------------------------------------------------
HRESULT CCredential::Connect(__in IQueryContinueWithStatus* pqcws)
{
    DebugPrint(__FUNCTION__);
    UNREFERENCED_PARAMETER(pqcws);

    // Read current field values
    ReadFieldValues();

    wstring username = _config->credential.username;

    // Check for excluded account
    if (_config->IsAccountExcluded(username, _config->credential.domain))
    {
        DebugPrint("Excluded account — skipping TOTP");
        _authSuccess = true;
        return S_OK;
    }

    // --- ENROLLMENT or OTP STEP (second press of Submit) ---
    if (_config->isSecondStep || _config->isEnrollment)
    {
        wstring otp = _config->credential.otp;
        if (otp.empty())
        {
            DebugPrint("OTP field is empty");
            _authSuccess = false;
            return S_OK;
        }

        // Get user SID
        wstring cleanUser = GetCleanUsername();
        wstring userSID = SecretStore::GetUserSID(cleanUser);
        if (userSID.empty())
        {
            DebugPrint("Could not resolve user SID");
            _authSuccess = false;
            return S_OK;
        }

        // Get the secret to validate against
        vector<uint8_t> secret;
        if (_config->isEnrollment && !_enrollmentSecret.empty())
        {
            // Use the enrollment secret (not yet stored)
            secret = _enrollmentSecret;
        }
        else
        {
            // Use the stored secret
            secret = SecretStore::GetSecret(userSID);
        }

        if (secret.empty())
        {
            DebugPrint("No TOTP secret available for validation");
            _authSuccess = false;
            return S_OK;
        }

        // Convert OTP to UTF-8
        string otpStr = TOTPEngine::WideToUTF8(otp);

        // Validate the TOTP code
        bool valid = TOTPEngine::ValidateCode(
            secret,
            otpStr,
            _config->totpDigits,
            _config->totpPeriod,
            _config->totpWindow
        );

        if (valid)
        {
            DebugPrint("TOTP validation successful!");
            _authSuccess = true;

            // If this was enrollment, store the secret and mark enrolled
            if (_config->isEnrollment)
            {
                HRESULT hr = SecretStore::StoreSecret(userSID, _enrollmentSecret);
                if (SUCCEEDED(hr))
                {
                    SecretStore::MarkEnrolled(userSID);
                    DebugPrint("Enrollment completed — secret stored");
                }
                else
                {
                    DebugPrint("Failed to store enrollment secret!");
                }

                // Clear enrollment state
                SecureZeroMemory(_enrollmentSecret.data(), _enrollmentSecret.size());
                _enrollmentSecret.clear();
                _enrollmentBase32.clear();
                _config->isEnrollment = false;
            }
        }
        else
        {
            DebugPrint("TOTP validation failed");
            _authSuccess = false;
        }

        return S_OK;
    }

    // --- FIRST STEP (password entered, need to check TOTP setup) ---
    wstring cleanUser = GetCleanUsername();
    wstring userSID = SecretStore::GetUserSID(cleanUser);

    if (!userSID.empty() && SecretStore::IsEnrolled(userSID))
    {
        // User is enrolled — move to OTP step
        DebugPrint("User is enrolled — switching to OTP step");
        _config->isSecondStep = true;
        _config->isEnrollment = false;
    }
    else
    {
        // User NOT enrolled — generate secret and prepare QR code
        DebugPrint("User not enrolled — generating TOTP secret for enrollment");

        _enrollmentSecret = TOTPEngine::GenerateSecret(20);
        _enrollmentBase32 = TOTPEngine::Base32Encode(_enrollmentSecret);

        // Build otpauth URI
        string usernameUTF8 = TOTPEngine::WideToUTF8(cleanUser);
        string issuerUTF8 = TOTPEngine::WideToUTF8(_config->issuerName);

        string otpauthURI = TOTPEngine::BuildOTPAuthURI(
            _enrollmentBase32, usernameUTF8, issuerUTF8,
            _config->totpDigits, _config->totpPeriod);

        DebugPrint("Generated otpauth URI for enrollment");

        // Generate QR code bitmap
        if (_hQRBitmap)
        {
            DeleteObject(_hQRBitmap);
            _hQRBitmap = nullptr;
        }
        _hQRBitmap = QRCode::GenerateBitmap(otpauthURI, 4);

        _config->isEnrollment = true;
        _config->isSecondStep = false;
    }

    // Delay briefly to prevent LogonUI freezing
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    return S_OK;
}

HRESULT CCredential::Disconnect()
{
    return E_NOTIMPL;
}

// ---------------------------------------------------------------------------
// GetSerialization — Called after Connect(). Either:
//   1. Switch to OTP/enrollment screen (CPGSR_NO_CREDENTIAL_NOT_FINISHED)
//   2. Pack credentials and logon (CPGSR_RETURN_CREDENTIAL_FINISHED)
//   3. Show error (CPGSR_NO_CREDENTIAL_NOT_FINISHED)
// ---------------------------------------------------------------------------
HRESULT CCredential::GetSerialization(
    __out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    __out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    __deref_out_opt PWSTR* ppwszOptionalStatusText,
    __out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    DebugPrint(__FUNCTION__);
    *pcpgsr = CPGSR_RETURN_NO_CREDENTIAL_FINISHED;

    _config->provider.pcpcs = pcpcs;
    _config->provider.pcpgsr = pcpgsr;
    _config->provider.status_icon = pcpsiOptionalStatusIcon;
    _config->provider.status_text = ppwszOptionalStatusText;

    HRESULT hr = E_FAIL;

    // --- AUTH SUCCESS: Pack Kerberos credentials and logon ---
    if (_authSuccess)
    {
        DebugPrint("Packing Kerberos credentials for logon");
        _authSuccess = false;

        // Build domain\username if needed
        wstring username = _config->credential.username;
        wstring domain = _config->credential.domain;
        wstring password = _config->credential.password;

        PWSTR pwzDomain = const_cast<LPWSTR>(domain.c_str());
        PWSTR pwzUsername = const_cast<LPWSTR>(username.c_str());
        PWSTR pwzPassword = const_cast<LPWSTR>(password.c_str());

        KERB_INTERACTIVE_UNLOCK_LOGON kiul;
        ZeroMemory(&kiul, sizeof(kiul));

        hr = KerbInteractiveUnlockLogonInit(
            pwzDomain, pwzUsername, pwzPassword,
            _config->provider.cpu, &kiul);

        if (SUCCEEDED(hr))
        {
            hr = KerbInteractiveUnlockLogonPack(kiul,
                &pcpcs->rgbSerialization, &pcpcs->cbSerialization);

            if (SUCCEEDED(hr))
            {
                ULONG authPackage = 0;
                hr = RetrieveNegotiateAuthPackage(&authPackage);
                if (SUCCEEDED(hr))
                {
                    pcpcs->ulAuthenticationPackage = authPackage;
                    pcpcs->clsidCredentialProvider = CLSID_TOTPCredentialProvider;
                    *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                }
            }
        }

        // Clear password from memory
        SecureZeroMemory(const_cast<wchar_t*>(password.c_str()),
            password.size() * sizeof(wchar_t));

        // Reset state
        _config->isSecondStep = false;
        _config->isEnrollment = false;

        return hr;
    }

    // --- ENROLLMENT: Show QR code and OTP input ---
    if (_config->isEnrollment)
    {
        DebugPrint("Showing enrollment screen with QR code");
        _config->clearFields = false;

        // Switch UI to enrollment scenario
        SetScenario(TOTP_SCENARIO::ENROLLMENT);

        // Set instruction text
        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, FID_LARGE_TEXT,
                L"Set Up Authenticator");

            wstring hint = L"Scan the QR code with your authenticator app, "
                L"then enter the code below.";
            _pCredProvCredentialEvents->SetFieldString(this, FID_SMALL_TEXT,
                hint.c_str());

            // Show the manual secret as fallback
            wstring secretDisplay = L"Manual key: " +
                TOTPEngine::UTF8ToWide(_enrollmentBase32);
            // We append it to the hint text
            hint += L"\n" + secretDisplay;
            _pCredProvCredentialEvents->SetFieldString(this, FID_SMALL_TEXT,
                hint.c_str());

            // Clear OTP field
            _pCredProvCredentialEvents->SetFieldString(this, FID_OTP, L"");

            // Move submit button next to OTP
            _pCredProvCredentialEvents->SetFieldSubmitButton(this,
                FID_SUBMIT_BUTTON, FID_OTP);
        }

        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_OK;
    }

    // --- OTP STEP: Show OTP input ---
    if (_config->isSecondStep && !_authSuccess)
    {
        // Check if we got here from a failed OTP attempt
        wstring otp = _config->credential.otp;
        if (!otp.empty())
        {
            // OTP was entered but validation failed
            DebugPrint("OTP validation failed — showing error");
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
            SHStrDupW(L"Invalid one-time password. Please try again.",
                ppwszOptionalStatusText);

            // Clear the OTP field for retry
            if (_pCredProvCredentialEvents)
                _pCredProvCredentialEvents->SetFieldString(this, FID_OTP, L"");

            _config->credential.otp = L"";
            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            return S_OK;
        }

        DebugPrint("Showing OTP input step");
        _config->clearFields = false;

        // Switch UI to OTP step
        SetScenario(TOTP_SCENARIO::OTP_STEP);

        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, FID_LARGE_TEXT,
                _config->loginText.c_str());

            wstring hint = L"Enter the code from your authenticator app.";
            _pCredProvCredentialEvents->SetFieldString(this, FID_SMALL_TEXT,
                hint.c_str());

            // Clear OTP field
            _pCredProvCredentialEvents->SetFieldString(this, FID_OTP, L"");

            // Move submit button next to OTP
            _pCredProvCredentialEvents->SetFieldSubmitButton(this,
                FID_SUBMIT_BUTTON, FID_OTP);
        }

        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_OK;
    }

    // Unexpected state
    DebugPrint("Unexpected state in GetSerialization");
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    return S_OK;
}

// ---------------------------------------------------------------------------
// ReportResult — Handle logon result from LSASS
// ---------------------------------------------------------------------------
HRESULT CCredential::ReportResult(
    __in NTSTATUS ntsStatus,
    __in NTSTATUS ntsSubstatus,
    __deref_out_opt PWSTR* ppwszOptionalStatusText,
    __out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    DebugPrint(__FUNCTION__);
    UNREFERENCED_PARAMETER(ppwszOptionalStatusText);
    UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);

    if (ntsStatus != 0)
    {
        DebugPrint("Logon failed — resetting to initial state");
        _config->isSecondStep = false;
        _config->isEnrollment = false;
        _authSuccess = false;

        // Reset UI to initial state
        if (_config->provider.cpu == CPUS_UNLOCK_WORKSTATION)
            SetScenario(TOTP_SCENARIO::UNLOCK_PASSWORD);
        else
            SetScenario(TOTP_SCENARIO::LOGON_PASSWORD_FIRST);
    }

    return S_OK;
}
