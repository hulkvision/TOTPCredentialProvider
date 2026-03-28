/* TOTP Credential Provider
 * CProvider.cpp — ICredentialProvider implementation
 *
 * Manages the credential tile lifecycle:
 * - SetUsageScenario: Determines if we support logon/unlock
 * - GetCredentialAt: Creates the CCredential tile
 * - GetFieldDescriptorAt: Returns field definitions
 *
 * Copyright 2026 — Apache License, Version 2.0
 */

#include "CProvider.h"
#include "Logger.h"
#include "scenario.h"
#include <credentialprovider.h>
#include <tchar.h>

using namespace std;

// Serialization check constants
#define SAF_USERNAME 0
#define SAF_PASSWORD 1
#define SAF_DOMAIN   2

CProvider::CProvider() :
    _cRef(1),
    _pkiulSetSerialization(nullptr),
    _credential(nullptr),
    _pCredProviderUserArray(nullptr)
{
    DllAddRef();

    // Force logging on for diagnostics
    Logger::Get().enabled = true;
    DebugPrint("CProvider::CProvider() - Provider created");

    _config = std::make_shared<Configuration>();
    Logger::Get().enabled = true; // Keep forced on (override config)

    DebugPrint("CProvider::CProvider() - Configuration loaded");
}

CProvider::~CProvider()
{
    if (_credential != nullptr)
    {
        _credential->Release();
        _credential = nullptr;
    }

    if (_pCredProviderUserArray != nullptr)
    {
        _pCredProviderUserArray->Release();
        _pCredProviderUserArray = nullptr;
    }

    DllRelease();
}

void CProvider::_CleanupSetSerialization()
{
    if (_pkiulSetSerialization)
    {
        KERB_INTERACTIVE_LOGON* pkil = &_pkiulSetSerialization->Logon;
        SecureZeroMemory(_pkiulSetSerialization,
            sizeof(*_pkiulSetSerialization) +
            pkil->LogonDomainName.MaximumLength +
            pkil->UserName.MaximumLength +
            pkil->Password.MaximumLength);
        HeapFree(GetProcessHeap(), 0, _pkiulSetSerialization);
    }
}

// ---------------------------------------------------------------------------
// SetUsageScenario — Called by LogonUI to tell us the login context
// ---------------------------------------------------------------------------
HRESULT CProvider::SetUsageScenario(
    __in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    __in DWORD dwFlags)
{
    DebugPrint(__FUNCTION__);

    HRESULT hr = E_INVALIDARG;

    _config->provider.credPackFlags = dwFlags;
    _config->provider.cpu = cpus;

    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        hr = S_OK;
        break;
    case CPUS_CREDUI:
    case CPUS_CHANGE_PASSWORD:
    case CPUS_PLAP:
    case CPUS_INVALID:
        hr = E_NOTIMPL;
        break;
    default:
        return E_INVALIDARG;
    }

    return hr;
}

// ---------------------------------------------------------------------------
// SetSerialization — Handle pre-populated credentials (e.g., from RDP)
// ---------------------------------------------------------------------------
HRESULT CProvider::SetSerialization(
    __in const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs)
{
    DebugPrint(__FUNCTION__);
    HRESULT result = E_NOTIMPL;
    ULONG authPackage = 0;
    result = RetrieveNegotiateAuthPackage(&authPackage);

    if (!SUCCEEDED(result))
        return result;

    if (authPackage == pcpcs->ulAuthenticationPackage &&
        pcpcs->cbSerialization > 0 && pcpcs->rgbSerialization)
    {
        KERB_INTERACTIVE_UNLOCK_LOGON* pkil =
            (KERB_INTERACTIVE_UNLOCK_LOGON*)pcpcs->rgbSerialization;

        if (pkil->Logon.MessageType == KerbInteractiveLogon)
        {
            if (pkil->Logon.UserName.Length && pkil->Logon.UserName.Buffer)
            {
                BYTE* native = (BYTE*)LocalAlloc(LMEM_ZEROINIT, pcpcs->cbSerialization);
                if (!native) return E_OUTOFMEMORY;

                CopyMemory(native, pcpcs->rgbSerialization, pcpcs->cbSerialization);
                KerbInteractiveUnlockLogonUnpackInPlace(
                    (KERB_INTERACTIVE_UNLOCK_LOGON*)native, pcpcs->cbSerialization);

                if (_pkiulSetSerialization)
                    LocalFree(_pkiulSetSerialization);

                _pkiulSetSerialization = (KERB_INTERACTIVE_UNLOCK_LOGON*)native;
                result = S_OK;
            }
        }
    }

    return result;
}

// ---------------------------------------------------------------------------
// Advise / UnAdvise — Callback management
// ---------------------------------------------------------------------------
HRESULT CProvider::Advise(
    __in ICredentialProviderEvents* pcpe,
    __in UINT_PTR upAdviseContext)
{
    if (_config->provider.pCredentialProviderEvents != nullptr)
        _config->provider.pCredentialProviderEvents->Release();

    _config->provider.pCredentialProviderEvents = pcpe;
    _config->provider.pCredentialProviderEvents->AddRef();
    _config->provider.upAdviseContext = upAdviseContext;

    return S_OK;
}

HRESULT CProvider::UnAdvise()
{
    if (_config->provider.pCredentialProviderEvents != nullptr)
        _config->provider.pCredentialProviderEvents->Release();

    _config->provider.pCredentialProviderEvents = nullptr;
    _config->provider.upAdviseContext = 0;

    return S_OK;
}

// ---------------------------------------------------------------------------
// GetFieldDescriptorCount / GetFieldDescriptorAt
// ---------------------------------------------------------------------------
HRESULT CProvider::GetFieldDescriptorCount(__out DWORD* pdwCount)
{
    *pdwCount = FID_NUM_FIELDS;
    return S_OK;
}

HRESULT CProvider::GetFieldDescriptorAt(
    __in DWORD dwIndex,
    __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
    HRESULT hr = E_FAIL;
    if ((dwIndex < FID_NUM_FIELDS) && ppcpfd)
    {
        // Customize field labels from config
        std::wstring label = L"";
        switch (dwIndex)
        {
        case FID_USERNAME:
            label = _config->usernameFieldText;
            if (label.empty()) label = L"Username";
            break;
        case FID_LDAP_PASS:
            label = _config->passFieldText;
            if (label.empty()) label = L"Password";
            break;
        case FID_OTP:
            label = _config->otpFieldText;
            if (label.empty()) label = L"One-Time Password";
            break;
        default:
            break;
        }

        if (!label.empty())
        {
            s_rgCredProvFieldDescriptors[dwIndex].pszLabel =
                const_cast<LPWSTR>(label.c_str());
        }

        hr = FieldDescriptorCoAllocCopy(
            s_rgCredProvFieldDescriptors[dwIndex], ppcpfd);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// ---------------------------------------------------------------------------
// GetCredentialCount / GetCredentialAt
// ---------------------------------------------------------------------------
HRESULT CProvider::GetCredentialCount(
    __out DWORD* pdwCount,
    __out_range(<, *pdwCount) DWORD* pdwDefault,
    __out BOOL* pbAutoLogonWithDefault)
{
    *pdwCount = 1;
    *pdwDefault = 0;
    *pbAutoLogonWithDefault = FALSE;

    if (_config->noDefault)
        *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;

    // If serialized creds available and user has already done password step
    if (_SerializationAvailable(SAF_USERNAME) &&
        _SerializationAvailable(SAF_PASSWORD))
    {
        *pdwDefault = 0;
        // Don't auto-logon; we still need OTP step
        *pbAutoLogonWithDefault = FALSE;
    }

    return S_OK;
}

HRESULT CProvider::GetCredentialAt(
    __in DWORD dwIndex,
    __deref_out ICredentialProviderCredential** ppcpc)
{
    DebugPrint(__FUNCTION__);
    HRESULT hr = E_FAIL;

    const CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus = _config->provider.cpu;

    if (!_credential)
    {
        PWSTR serializedUser = nullptr, serializedPass = nullptr, serializedDomain = nullptr;
        _GetSerializedCredentials(&serializedUser, &serializedPass, &serializedDomain);

        if (cpus == CPUS_UNLOCK_WORKSTATION && !serializedUser)
        {
            DWORD dwLen = 0;
            WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE,
                WTS_CURRENT_SESSION, WTSUserName, &serializedUser, &dwLen);
            if (!serializedUser) serializedUser = nullptr;

            if (!serializedDomain)
            {
                dwLen = 0;
                WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE,
                    WTS_CURRENT_SESSION, WTSDomainName, &serializedDomain, &dwLen);
                if (!serializedDomain) serializedDomain = nullptr;
            }
        }
        else if (cpus == CPUS_LOGON)
        {
            if (!serializedDomain)
            {
                NETSETUP_JOIN_STATUS join_status;
                if (NetGetJoinInformation(nullptr, &serializedDomain, &join_status)
                    != NERR_Success ||
                    join_status == NetSetupUnjoined ||
                    join_status == NetSetupUnknownStatus ||
                    join_status == NetSetupWorkgroupName)
                {
                    serializedDomain = nullptr;
                }
            }
        }

        // Determine initial field state based on scenario
        const FIELD_STATE_PAIR* fieldStates;
        if (cpus == CPUS_UNLOCK_WORKSTATION)
            fieldStates = s_rgScenarioUnlockPassword;
        else
            fieldStates = s_rgScenarioLogonPasswordFirst;

        _credential = new (std::nothrow) CCredential(_config);
        if (!_credential)
            return E_OUTOFMEMORY;

        hr = _credential->Initialize(
            s_rgCredProvFieldDescriptors,
            fieldStates,
            serializedUser, serializedDomain, serializedPass);
    }
    else
    {
        hr = S_OK;
    }

    if (FAILED(hr)) return hr;
    if (!_credential) return E_OUTOFMEMORY;

    if ((dwIndex == 0) && ppcpc)
    {
        hr = _credential->QueryInterface(
            IID_IConnectableCredentialProviderCredential,
            reinterpret_cast<void**>(ppcpc));
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// ---------------------------------------------------------------------------
// SetUserArray
// ---------------------------------------------------------------------------
HRESULT CProvider::SetUserArray(_In_ ICredentialProviderUserArray* users)
{
    if (_pCredProviderUserArray)
    {
        _pCredProviderUserArray->Release();
    }
    _pCredProviderUserArray = users;
    _pCredProviderUserArray->AddRef();
    return S_OK;
}

// ---------------------------------------------------------------------------
// CreateInstance — Factory method called from DLL
// ---------------------------------------------------------------------------
HRESULT TOTPProvider_CreateInstance(__in REFIID riid, __deref_out void** ppv)
{
    HRESULT hr;
    CProvider* pProvider = new CProvider();
    if (pProvider)
    {
        hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }
    return hr;
}

// ---------------------------------------------------------------------------
// Serialized credentials helpers
// ---------------------------------------------------------------------------
void CProvider::_GetSerializedCredentials(PWSTR* username, PWSTR* password, PWSTR* domain)
{
    if (username)
    {
        if (_SerializationAvailable(SAF_USERNAME))
        {
            *username = (PWSTR)LocalAlloc(LMEM_ZEROINIT,
                _pkiulSetSerialization->Logon.UserName.Length + sizeof(wchar_t));
            CopyMemory(*username,
                _pkiulSetSerialization->Logon.UserName.Buffer,
                _pkiulSetSerialization->Logon.UserName.Length);
        }
        else *username = nullptr;
    }

    if (password)
    {
        if (_SerializationAvailable(SAF_PASSWORD))
        {
            *password = (PWSTR)LocalAlloc(LMEM_ZEROINIT,
                _pkiulSetSerialization->Logon.Password.Length + sizeof(wchar_t));
            CopyMemory(*password,
                _pkiulSetSerialization->Logon.Password.Buffer,
                _pkiulSetSerialization->Logon.Password.Length);
        }
        else *password = nullptr;
    }

    if (domain)
    {
        if (_SerializationAvailable(SAF_DOMAIN))
        {
            *domain = (PWSTR)LocalAlloc(LMEM_ZEROINIT,
                _pkiulSetSerialization->Logon.LogonDomainName.Length + sizeof(wchar_t));
            CopyMemory(*domain,
                _pkiulSetSerialization->Logon.LogonDomainName.Buffer,
                _pkiulSetSerialization->Logon.LogonDomainName.Length);
        }
        else *domain = nullptr;
    }
}

bool CProvider::_SerializationAvailable(int checkFor)
{
    if (!_pkiulSetSerialization) return false;

    switch (checkFor)
    {
    case SAF_USERNAME:
        return _pkiulSetSerialization->Logon.UserName.Length &&
               _pkiulSetSerialization->Logon.UserName.Buffer;
    case SAF_PASSWORD:
        return _pkiulSetSerialization->Logon.Password.Length &&
               _pkiulSetSerialization->Logon.Password.Buffer;
    case SAF_DOMAIN:
        return _pkiulSetSerialization->Logon.LogonDomainName.Length &&
               _pkiulSetSerialization->Logon.LogonDomainName.Buffer;
    }
    return false;
}
