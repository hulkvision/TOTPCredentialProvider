/* TOTP Credential Provider
 * Dll.cpp — COM DLL entry points and class factory
 *
 * Copyright 2026 — Apache License, Version 2.0
 */

#include "Dll.h"
#include "guid.h"

static LONG g_cRef = 0;
HINSTANCE g_hinst = nullptr;

extern HRESULT TOTPProvider_CreateInstance(__in REFIID riid, __deref_out void** ppv);
EXTERN_C GUID CLSID_TOTPCredentialProvider;

// ---------------------------------------------------------------------------
// CClassFactory — Standard COM class factory
// ---------------------------------------------------------------------------
class CClassFactory : public IClassFactory
{
public:
    CClassFactory() : _cRef(1) {}

    // IUnknown
#pragma warning(disable : 4838)
    IFACEMETHODIMP QueryInterface(__in REFIID riid, __deref_out void** ppv) noexcept
    {
        static const QITAB qit[] =
        {
            QITABENT(CClassFactory, IClassFactory),
            { 0 },
        };
        return QISearch(this, qit, riid, ppv);
    }

    IFACEMETHODIMP_(ULONG) AddRef() noexcept
    {
        return InterlockedIncrement(&_cRef);
    }

    IFACEMETHODIMP_(ULONG) Release() noexcept
    {
        LONG const cRef = InterlockedDecrement(&_cRef);
        if (!cRef)
            delete this;
        return cRef;
    }

    // IClassFactory
    IFACEMETHODIMP CreateInstance(__in IUnknown* pUnkOuter, __in REFIID riid, __deref_out void** ppv)
    {
        HRESULT hr;
        if (!pUnkOuter)
        {
            hr = TOTPProvider_CreateInstance(riid, ppv);
        }
        else
        {
            *ppv = nullptr;
            hr = CLASS_E_NOAGGREGATION;
        }
        return hr;
    }

    IFACEMETHODIMP LockServer(__in BOOL bLock)
    {
        if (bLock) DllAddRef();
        else       DllRelease();
        return S_OK;
    }

private:
    ~CClassFactory() {}
    long _cRef;
};

// ---------------------------------------------------------------------------
// DLL exports
// ---------------------------------------------------------------------------
static HRESULT CClassFactory_CreateInstance(__in REFCLSID rclsid, __in REFIID riid, __deref_out void** ppv)
{
    *ppv = nullptr;
    HRESULT hr;

    if (CLSID_TOTPCredentialProvider == rclsid)
    {
        CClassFactory* pcf = new CClassFactory();
        if (pcf)
        {
            hr = pcf->QueryInterface(riid, ppv);
            pcf->Release();
        }
        else
        {
            hr = E_OUTOFMEMORY;
        }
    }
    else
    {
        hr = CLASS_E_CLASSNOTAVAILABLE;
    }
    return hr;
}

void DllAddRef() noexcept
{
    InterlockedIncrement(&g_cRef);
}

void DllRelease() noexcept
{
    InterlockedDecrement(&g_cRef);
}

STDAPI DllCanUnloadNow()
{
    return (g_cRef > 0) ? S_FALSE : S_OK;
}

STDAPI DllGetClassObject(__in REFCLSID rclsid, __in REFIID riid, __deref_out void** ppv)
{
    return CClassFactory_CreateInstance(rclsid, riid, ppv);
}

STDAPI_(BOOL) DllMain(__in HINSTANCE hinstDll, __in DWORD dwReason, __in void*)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDll);
        break;
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    g_hinst = hinstDll;
    return TRUE;
}
