/* TOTP Credential Provider
 * helpers.cpp — Kerberos logon serialization helpers implementation
 *
 * Based on Microsoft Credential Provider samples and
 * the multiOTP credential provider helpers.
 *
 * Copyright 2026 — Apache License, Version 2.0
 */

#include "helpers.h"
#include <intsafe.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "secur32.lib")

// ---------------------------------------------------------------------------
// FieldDescriptorCoAllocCopy
// ---------------------------------------------------------------------------
HRESULT FieldDescriptorCoAllocCopy(
    __in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
    __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
    HRESULT hr;
    DWORD cbStruct = sizeof(**ppcpfd);

    *ppcpfd = (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(cbStruct);
    if (*ppcpfd)
    {
        (*ppcpfd)->dwFieldID = rcpfd.dwFieldID;
        (*ppcpfd)->cpft = rcpfd.cpft;
        (*ppcpfd)->guidFieldType = rcpfd.guidFieldType;

        if (rcpfd.pszLabel)
        {
            hr = SHStrDupW(rcpfd.pszLabel, &(*ppcpfd)->pszLabel);
        }
        else
        {
            (*ppcpfd)->pszLabel = nullptr;
            hr = S_OK;
        }
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

    return hr;
}

// ---------------------------------------------------------------------------
// FieldDescriptorCopy
// ---------------------------------------------------------------------------
HRESULT FieldDescriptorCopy(
    __in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
    __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd)
{
    HRESULT hr;

    pcpfd->dwFieldID = rcpfd.dwFieldID;
    pcpfd->cpft = rcpfd.cpft;
    pcpfd->guidFieldType = rcpfd.guidFieldType;

    if (rcpfd.pszLabel)
    {
        size_t cb = (wcslen(rcpfd.pszLabel) + 1) * sizeof(WCHAR);
        pcpfd->pszLabel = (PWSTR)HeapAlloc(GetProcessHeap(), 0, cb);
        if (pcpfd->pszLabel)
        {
            hr = StringCbCopyW(pcpfd->pszLabel, cb, rcpfd.pszLabel);
        }
        else
        {
            hr = E_OUTOFMEMORY;
        }
    }
    else
    {
        pcpfd->pszLabel = nullptr;
        hr = S_OK;
    }

    return hr;
}

// ---------------------------------------------------------------------------
// UnicodeStringInitWithString
// ---------------------------------------------------------------------------
HRESULT UnicodeStringInitWithString(
    __in PWSTR pwz,
    __out UNICODE_STRING* pus)
{
    HRESULT hr;
    if (pwz)
    {
        size_t lenBytes = wcslen(pwz) * sizeof(WCHAR);
        if (lenBytes <= USHRT_MAX)
        {
            pus->Buffer = pwz;
            pus->Length = (USHORT)lenBytes;
            pus->MaximumLength = pus->Length;
            hr = S_OK;
        }
        else
        {
            hr = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// ---------------------------------------------------------------------------
// _UnicodeStringPackedUnicodeStringCopy
// ---------------------------------------------------------------------------
static void _UnicodeStringPackedUnicodeStringCopy(
    const UNICODE_STRING& rus,
    PWSTR pwzBuffer,
    UNICODE_STRING* pus)
{
    pus->Length = rus.Length;
    pus->MaximumLength = rus.Length;
    pus->Buffer = pwzBuffer;

    CopyMemory(pus->Buffer, rus.Buffer, pus->Length);
}

// ---------------------------------------------------------------------------
// KerbInteractiveUnlockLogonInit
// ---------------------------------------------------------------------------
HRESULT KerbInteractiveUnlockLogonInit(
    __in PWSTR pwzDomain,
    __in PWSTR pwzUsername,
    __in PWSTR pwzPassword,
    __in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    __out KERB_INTERACTIVE_UNLOCK_LOGON* pkiul)
{
    KERB_INTERACTIVE_UNLOCK_LOGON kiul;
    ZeroMemory(&kiul, sizeof(kiul));

    KERB_INTERACTIVE_LOGON* pkil = &kiul.Logon;

    HRESULT hr = UnicodeStringInitWithString(pwzDomain, &pkil->LogonDomainName);
    if (SUCCEEDED(hr))
    {
        hr = UnicodeStringInitWithString(pwzUsername, &pkil->UserName);
        if (SUCCEEDED(hr))
        {
            hr = UnicodeStringInitWithString(pwzPassword, &pkil->Password);
            if (SUCCEEDED(hr))
            {
                pkil->MessageType = KerbInteractiveLogon;

                if (cpus == CPUS_UNLOCK_WORKSTATION)
                {
                    // For unlock, the message type on the Logon struct
                    // indicates this is a workstation unlock
                    pkil->MessageType = KerbWorkstationUnlockLogon;
                }

                *pkiul = kiul;
            }
        }
    }

    return hr;
}

// ---------------------------------------------------------------------------
// KerbInteractiveUnlockLogonPack
// ---------------------------------------------------------------------------
HRESULT KerbInteractiveUnlockLogonPack(
    __in const KERB_INTERACTIVE_UNLOCK_LOGON& rkiulIn,
    __deref_out_bcount(*pcb) BYTE** prgb,
    __out DWORD* pcb)
{
    const KERB_INTERACTIVE_LOGON* pkilIn = &rkiulIn.Logon;

    DWORD cb = sizeof(rkiulIn) +
        pkilIn->LogonDomainName.Length +
        pkilIn->UserName.Length +
        pkilIn->Password.Length;

    KERB_INTERACTIVE_UNLOCK_LOGON* pkiulOut =
        (KERB_INTERACTIVE_UNLOCK_LOGON*)CoTaskMemAlloc(cb);

    if (pkiulOut)
    {
        ZeroMemory(&pkiulOut->LogonId, sizeof(pkiulOut->LogonId));

        KERB_INTERACTIVE_LOGON* pkilOut = &pkiulOut->Logon;
        pkilOut->MessageType = pkilIn->MessageType;

        BYTE* pbBuffer = (BYTE*)pkiulOut + sizeof(*pkiulOut);

        _UnicodeStringPackedUnicodeStringCopy(
            pkilIn->LogonDomainName, (PWSTR)pbBuffer,
            &pkilOut->LogonDomainName);
        pkilOut->LogonDomainName.Buffer =
            (PWSTR)((BYTE*)pkilOut->LogonDomainName.Buffer - (BYTE*)pkiulOut);
        pbBuffer += pkilOut->LogonDomainName.Length;

        _UnicodeStringPackedUnicodeStringCopy(
            pkilIn->UserName, (PWSTR)pbBuffer,
            &pkilOut->UserName);
        pkilOut->UserName.Buffer =
            (PWSTR)((BYTE*)pkilOut->UserName.Buffer - (BYTE*)pkiulOut);
        pbBuffer += pkilOut->UserName.Length;

        _UnicodeStringPackedUnicodeStringCopy(
            pkilIn->Password, (PWSTR)pbBuffer,
            &pkilOut->Password);
        pkilOut->Password.Buffer =
            (PWSTR)((BYTE*)pkilOut->Password.Buffer - (BYTE*)pkiulOut);

        *prgb = (BYTE*)pkiulOut;
        *pcb = cb;

        return S_OK;
    }
    else
    {
        *prgb = nullptr;
        *pcb = 0;
        return E_OUTOFMEMORY;
    }
}

// ---------------------------------------------------------------------------
// RetrieveNegotiateAuthPackage
// ---------------------------------------------------------------------------
HRESULT RetrieveNegotiateAuthPackage(__out ULONG* pulAuthPackage)
{
    HRESULT hr;
    HANDLE hLsa;

    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (SUCCEEDED(HRESULT_FROM_NT(status)))
    {
        ULONG ulAuthPackage;
        LSA_STRING lsaszKerberosName;
        lsaszKerberosName.Buffer = (PCHAR)NEGOSSP_NAME_A;
        lsaszKerberosName.Length = (USHORT)strlen(lsaszKerberosName.Buffer);
        lsaszKerberosName.MaximumLength = lsaszKerberosName.Length + 1;

        status = LsaLookupAuthenticationPackage(hLsa, &lsaszKerberosName,
            &ulAuthPackage);
        if (SUCCEEDED(HRESULT_FROM_NT(status)))
        {
            *pulAuthPackage = ulAuthPackage;
            hr = S_OK;
        }
        else
        {
            hr = HRESULT_FROM_NT(status);
        }
        LsaDeregisterLogonProcess(hLsa);
    }
    else
    {
        hr = HRESULT_FROM_NT(status);
    }

    return hr;
}

// ---------------------------------------------------------------------------
// ProtectIfNecessaryAndCopyPassword
// ---------------------------------------------------------------------------
HRESULT ProtectIfNecessaryAndCopyPassword(
    __in PCWSTR pwzPassword,
    __in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    __deref_out PWSTR* ppwzProtectedPassword)
{
    *ppwzProtectedPassword = nullptr;
    HRESULT hr;

    // ProtectIfNecessaryAndCopyPassword is intended for use with
    // CPUS_LOGON and CPUS_UNLOCK_WORKSTATION.
    if (cpus != CPUS_CHANGE_PASSWORD)
    {
        CRED_PROTECTION_TYPE protectionType;
        if (CredIsProtectedW(const_cast<PWSTR>(pwzPassword), &protectionType))
        {
            if (CredUnprotected == protectionType)
            {
                DWORD cchProtected = 0;
                if (!CredProtectW(FALSE, const_cast<PWSTR>(pwzPassword),
                    (DWORD)wcslen(pwzPassword) + 1,
                    nullptr, &cchProtected, nullptr))
                {
                    DWORD dwErr = GetLastError();
                    if ((ERROR_INSUFFICIENT_BUFFER == dwErr) && (0 < cchProtected))
                    {
                        PWSTR pwzProtected = (PWSTR)CoTaskMemAlloc(cchProtected * sizeof(WCHAR));
                        if (pwzProtected)
                        {
                            if (CredProtectW(FALSE, const_cast<PWSTR>(pwzPassword),
                                (DWORD)wcslen(pwzPassword) + 1,
                                pwzProtected, &cchProtected, nullptr))
                            {
                                *ppwzProtectedPassword = pwzProtected;
                                hr = S_OK;
                            }
                            else
                            {
                                CoTaskMemFree(pwzProtected);
                                hr = HRESULT_FROM_WIN32(GetLastError());
                            }
                        }
                        else
                        {
                            hr = E_OUTOFMEMORY;
                        }
                    }
                    else
                    {
                        hr = HRESULT_FROM_WIN32(dwErr);
                    }
                }
                else
                {
                    hr = E_UNEXPECTED;
                }
            }
            else
            {
                hr = SHStrDupW(pwzPassword, ppwzProtectedPassword);
            }
        }
        else
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
        }
    }
    else
    {
        hr = SHStrDupW(pwzPassword, ppwzProtectedPassword);
    }

    return hr;
}

// ---------------------------------------------------------------------------
// KerbInteractiveUnlockLogonRepackNative
// ---------------------------------------------------------------------------
HRESULT KerbInteractiveUnlockLogonRepackNative(
    __in_bcount(cbWow) BYTE* rgbWow,
    __in DWORD cbWow,
    __deref_out_bcount(*pcbNative) BYTE** prgbNative,
    __out DWORD* pcbNative)
{
    HRESULT hr = E_FAIL;
    KERB_INTERACTIVE_UNLOCK_LOGON* pkiul =
        (KERB_INTERACTIVE_UNLOCK_LOGON*)rgbWow;

    if (sizeof(*pkiul) <= cbWow)
    {
        KerbInteractiveUnlockLogonUnpackInPlace(pkiul, cbWow);
        hr = KerbInteractiveUnlockLogonPack(*pkiul, prgbNative, pcbNative);
    }

    return hr;
}

// ---------------------------------------------------------------------------
// KerbInteractiveUnlockLogonUnpackInPlace
// ---------------------------------------------------------------------------
void KerbInteractiveUnlockLogonUnpackInPlace(
    __inout_bcount(cb) KERB_INTERACTIVE_UNLOCK_LOGON* pkiul,
    __in DWORD cb)
{
    UNREFERENCED_PARAMETER(cb);
    KERB_INTERACTIVE_LOGON* pkil = &pkiul->Logon;

    pkil->LogonDomainName.Buffer =
        pkil->LogonDomainName.Buffer
        ? (PWSTR)((BYTE*)pkiul + (ULONG_PTR)pkil->LogonDomainName.Buffer)
        : nullptr;

    pkil->UserName.Buffer =
        pkil->UserName.Buffer
        ? (PWSTR)((BYTE*)pkiul + (ULONG_PTR)pkil->UserName.Buffer)
        : nullptr;

    pkil->Password.Buffer =
        pkil->Password.Buffer
        ? (PWSTR)((BYTE*)pkiul + (ULONG_PTR)pkil->Password.Buffer)
        : nullptr;
}

// ---------------------------------------------------------------------------
// DomainUsernameStringAlloc
// ---------------------------------------------------------------------------
HRESULT DomainUsernameStringAlloc(
    __in PCWSTR pwszDomain,
    __in PCWSTR pwszUsername,
    __deref_out PWSTR* ppwszDomainUsername)
{
    HRESULT hr;
    size_t cchDomain = wcslen(pwszDomain);
    size_t cchUsername = wcslen(pwszUsername);
    size_t cchLen = cchDomain + 1 + cchUsername; // domain\username

    *ppwszDomainUsername = (PWSTR)CoTaskMemAlloc((cchLen + 1) * sizeof(WCHAR));
    if (*ppwszDomainUsername)
    {
        hr = StringCchPrintfW(*ppwszDomainUsername, cchLen + 1,
            L"%s\\%s", pwszDomain, pwszUsername);
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

    return hr;
}
