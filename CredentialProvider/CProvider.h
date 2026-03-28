/* TOTP Credential Provider
 * CProvider.h — ICredentialProvider implementation
 *
 * Manages the credential tile lifecycle for Windows LogonUI.
 *
 * Copyright 2026 — Apache License, Version 2.0
 */

#pragma once

#include <windows.h>
#include <strsafe.h>
#include <credentialprovider.h>
#include <Wtsapi32.h>
#include <Lm.h>

#include "helpers.h"
#include "CCredential.h"
#include "Configuration.h"

#include <memory>

class CProvider : public ICredentialProvider, public ICredentialProviderSetUserArray
{
public:
    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef()
    {
        return InterlockedIncrement(&_cRef);
    }

    IFACEMETHODIMP_(ULONG) Release()
    {
        LONG cRef = InterlockedDecrement(&_cRef);
        if (!cRef)
            delete this;
        return cRef;
    }

#pragma warning(disable : 4838)
    IFACEMETHODIMP QueryInterface(__in REFIID riid, __deref_out void** ppv)
    {
        static const QITAB qit[] =
        {
            QITABENT(CProvider, ICredentialProvider),
            QITABENT(CProvider, ICredentialProviderSetUserArray),
            { 0 },
        };
        return QISearch(this, qit, riid, ppv);
    }

public:
    // ICredentialProvider
    IFACEMETHODIMP SetUsageScenario(__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
        __in DWORD dwFlags) override;
    IFACEMETHODIMP SetSerialization(
        __in const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs) override;

    IFACEMETHODIMP Advise(__in ICredentialProviderEvents* pcpe,
        __in UINT_PTR upAdviseContext) override;
    IFACEMETHODIMP UnAdvise() override;

    IFACEMETHODIMP GetFieldDescriptorCount(__out DWORD* pdwCount) override;
    IFACEMETHODIMP GetFieldDescriptorAt(__in DWORD dwIndex,
        __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd) override;

    IFACEMETHODIMP GetCredentialCount(__out DWORD* pdwCount,
        __out_range(<, *pdwCount) DWORD* pdwDefault,
        __out BOOL* pbAutoLogonWithDefault) override;

    IFACEMETHODIMP GetCredentialAt(__in DWORD dwIndex,
        __deref_out ICredentialProviderCredential** ppcpc) override;

    // ICredentialProviderSetUserArray
    IFACEMETHODIMP SetUserArray(_In_ ICredentialProviderUserArray* users);

    friend HRESULT TOTPProvider_CreateInstance(__in REFIID riid, __deref_out void** ppv);

protected:
    CProvider();
    __override ~CProvider();

private:
    void _CleanupSetSerialization();
    void _GetSerializedCredentials(PWSTR* username, PWSTR* password, PWSTR* domain);
    bool _SerializationAvailable(int checkFor);

private:
    LONG                                    _cRef;
    KERB_INTERACTIVE_UNLOCK_LOGON*          _pkiulSetSerialization;
    CCredential*                            _credential;
    std::shared_ptr<Configuration>          _config;
    ICredentialProviderUserArray*            _pCredProviderUserArray;
};
