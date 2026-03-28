/* TOTP Credential Provider Filter
 * CFilter.h - ICredentialProviderFilter implementation
 *
 * This filter hides all other credential providers during logon/unlock,
 * so only the TOTP Credential Provider tile is shown.
 */

#pragma once

#include <windows.h>
#include <credentialprovider.h>
#include <shlwapi.h>
#include "Dll.h"

class CFilter : public ICredentialProviderFilter
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

    IFACEMETHODIMP QueryInterface(__in REFIID riid, __deref_out void** ppv)
    {
        HRESULT hr;
        if (IID_IUnknown == riid || IID_ICredentialProviderFilter == riid)
        {
            *ppv = static_cast<ICredentialProviderFilter*>(this);
            reinterpret_cast<IUnknown*>(*ppv)->AddRef();
            hr = S_OK;
        }
        else
        {
            *ppv = nullptr;
            hr = E_NOINTERFACE;
        }
        return hr;
    }

public:
    // ICredentialProviderFilter
    IFACEMETHODIMP Filter(
        CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
        DWORD dwFlags,
        GUID* rgclsidProviders,
        BOOL* rgbAllow,
        DWORD cProviders);

    IFACEMETHODIMP UpdateRemoteCredential(
        const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsIn,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsOut);

    friend HRESULT TOTPFilter_CreateInstance(__in REFIID riid, __deref_out void** ppv);

protected:
    CFilter();
    ~CFilter();

private:
    LONG _cRef;
};
