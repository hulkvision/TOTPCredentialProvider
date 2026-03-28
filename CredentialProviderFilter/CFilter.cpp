/* TOTP Credential Provider Filter
 * CFilter.cpp - ICredentialProviderFilter implementation
 *
 * Blocks all credential providers except our TOTP provider during
 * CPUS_LOGON and CPUS_UNLOCK_WORKSTATION scenarios.
 * This forces users through the TOTP login flow.
 */

#include "CFilter.h"
#include "guid.h"

// ---------------------------------------------------------------------------
// Factory function (called from Dll.cpp CClassFactory)
// ---------------------------------------------------------------------------
HRESULT TOTPFilter_CreateInstance(__in REFIID riid, __deref_out void** ppv)
{
    HRESULT hr;
    CFilter* pFilter = new CFilter();

    if (pFilter)
    {
        hr = pFilter->QueryInterface(riid, ppv);
        pFilter->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

    return hr;
}

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------
CFilter::CFilter() : _cRef(1)
{
    DllAddRef();
}

CFilter::~CFilter()
{
    DllRelease();
}

// ---------------------------------------------------------------------------
// Filter - Called by LogonUI to decide which providers to show
//
// For each provider in rgclsidProviders, set rgbAllow[i] to:
//   TRUE  = show this provider
//   FALSE = hide this provider
//
// We only allow our TOTP provider; all others are hidden.
// ---------------------------------------------------------------------------
HRESULT CFilter::Filter(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD dwFlags,
    GUID* rgclsidProviders,
    BOOL* rgbAllow,
    DWORD cProviders)
{
    UNREFERENCED_PARAMETER(dwFlags);

    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        // Filter out all providers except ours
        for (DWORD i = 0; i < cProviders; i++)
        {
            if (IsEqualGUID(rgclsidProviders[i], CLSID_TOTPCredentialProvider))
            {
                rgbAllow[i] = TRUE;   // Allow our TOTP provider
            }
            else
            {
                rgbAllow[i] = FALSE;  // Block everything else
            }
        }
        break;

    case CPUS_CREDUI:
        // Don't filter CredUI (UAC prompts etc.) - allow all
        break;

    case CPUS_CHANGE_PASSWORD:
        return E_NOTIMPL;

    default:
        return E_INVALIDARG;
    }

    return S_OK;
}

// ---------------------------------------------------------------------------
// UpdateRemoteCredential - For remote/RDP scenarios
// Route remote credentials to our provider
// ---------------------------------------------------------------------------
HRESULT CFilter::UpdateRemoteCredential(
    const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsIn,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsOut)
{
    if (!pcpcsIn)
        return E_NOTIMPL;

    // Copy incoming serialization
    pcpcsOut->ulAuthenticationPackage = pcpcsIn->ulAuthenticationPackage;
    pcpcsOut->cbSerialization = pcpcsIn->cbSerialization;
    pcpcsOut->rgbSerialization = pcpcsIn->rgbSerialization;

    // Route to our credential provider
    pcpcsOut->clsidCredentialProvider = CLSID_TOTPCredentialProvider;

    // Copy buffer if needed
    if (pcpcsOut->cbSerialization > 0 &&
        (pcpcsOut->rgbSerialization = (BYTE*)CoTaskMemAlloc(pcpcsIn->cbSerialization)) != NULL)
    {
        CopyMemory(pcpcsOut->rgbSerialization, pcpcsIn->rgbSerialization, pcpcsIn->cbSerialization);
        return S_OK;
    }

    return E_NOTIMPL;
}
