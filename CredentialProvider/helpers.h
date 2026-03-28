/* TOTP Credential Provider
 * helpers.h — Kerberos logon serialization helpers
 *
 * Standard helper functions for packaging Windows credentials
 * into the format expected by LogonUI/LSASS.
 *
 * Based on Microsoft Credential Provider samples.
 *
 * Copyright 2026 — Apache License, Version 2.0
 */

#pragma once

#include <credentialprovider.h>
#include <ntsecapi.h>
#define SECURITY_WIN32
#include <security.h>
#include <intsafe.h>
#include <windows.h>
#include <strsafe.h>

#pragma warning(push)
#pragma warning(disable : 4995)
#include <shlwapi.h>
#pragma warning(pop)

// Makes a copy of a field descriptor using CoTaskMemAlloc
HRESULT FieldDescriptorCoAllocCopy(
    __in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
    __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd
);

// Makes a copy of a field descriptor on the normal heap
HRESULT FieldDescriptorCopy(
    __in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
    __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd
);

// Creates a UNICODE_STRING from a NULL-terminated string
HRESULT UnicodeStringInitWithString(
    __in PWSTR pwz,
    __out UNICODE_STRING* pus
);

// Initializes a KERB_INTERACTIVE_UNLOCK_LOGON with weak references
HRESULT KerbInteractiveUnlockLogonInit(
    __in PWSTR pwzDomain,
    __in PWSTR pwzUsername,
    __in PWSTR pwzPassword,
    __in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    __out KERB_INTERACTIVE_UNLOCK_LOGON* pkiul
);

// Packages the credentials into the buffer the system expects
HRESULT KerbInteractiveUnlockLogonPack(
    __in const KERB_INTERACTIVE_UNLOCK_LOGON& rkiulIn,
    __deref_out_bcount(*pcb) BYTE** prgb,
    __out DWORD* pcb
);

// Gets the authentication package for logon
HRESULT RetrieveNegotiateAuthPackage(
    __out ULONG* pulAuthPackage
);

// Encrypt a password if necessary and copy it
HRESULT ProtectIfNecessaryAndCopyPassword(
    __in PCWSTR pwzPassword,
    __in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    __deref_out PWSTR* ppwzProtectedPassword
);

HRESULT KerbInteractiveUnlockLogonRepackNative(
    __in_bcount(cbWow) BYTE* rgbWow,
    __in DWORD cbWow,
    __deref_out_bcount(*pcbNative) BYTE** prgbNative,
    __out DWORD* pcbNative
);

void KerbInteractiveUnlockLogonUnpackInPlace(
    __inout_bcount(cb) KERB_INTERACTIVE_UNLOCK_LOGON* pkiul,
    __in DWORD cb
);

HRESULT DomainUsernameStringAlloc(
    __in PCWSTR pwszDomain,
    __in PCWSTR pwszUsername,
    __deref_out PWSTR* ppwszDomainUsername
);
