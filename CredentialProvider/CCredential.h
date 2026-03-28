/* TOTP Credential Provider
 * CCredential.h — IConnectableCredentialProviderCredential implementation
 *
 * Handles the actual login flow:
 * 1. Password step → validate against Windows
 * 2. OTP step → validate TOTP code
 * 3. Enrollment → show QR code, validate first OTP to confirm setup
 *
 * Copyright 2026 — Apache License, Version 2.0
 */

#pragma once

#include "Dll.h"
#include "Configuration.h"
#include "TOTPEngine.h"
#include "QRCode.h"
#include "SecretStore.h"
#include "scenario.h"
#include "helpers.h"

#include <unknwn.h>
#include <string>
#include <memory>
#include <vector>

#define NOT_EMPTY(NAME) (NAME != NULL && NAME[0] != NULL)
#define ZERO(NAME) SecureZeroMemory(NAME, sizeof(NAME))

class CCredential : public IConnectableCredentialProviderCredential
{
public:
    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef() noexcept { return ++_cRef; }
    IFACEMETHODIMP_(ULONG) Release() noexcept
    {
        LONG cRef = --_cRef;
        if (!cRef) { /* Owned by CProvider */ }
        return cRef;
    }

#pragma warning(disable : 4838)
    IFACEMETHODIMP QueryInterface(__in REFIID riid, __deref_out void** ppv)
    {
        static const QITAB qit[] =
        {
            QITABENT(CCredential, ICredentialProviderCredential),
            QITABENT(CCredential, IConnectableCredentialProviderCredential),
            { 0 },
        };
        return QISearch(this, qit, riid, ppv);
    }

public:
    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(__in ICredentialProviderCredentialEvents* pcpce);
    IFACEMETHODIMP UnAdvise();

    IFACEMETHODIMP SetSelected(__out BOOL* pbAutoLogon);
    IFACEMETHODIMP SetDeselected();

    IFACEMETHODIMP GetFieldState(__in DWORD dwFieldID,
        __out CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
        __out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis);

    IFACEMETHODIMP GetStringValue(__in DWORD dwFieldID, __deref_out PWSTR* ppwsz);
    IFACEMETHODIMP GetBitmapValue(__in DWORD dwFieldID, __out HBITMAP* phbmp);
    IFACEMETHODIMP GetCheckboxValue(__in DWORD dwFieldID,
        __out BOOL* pbChecked, __deref_out PWSTR* ppwszLabel);
    IFACEMETHODIMP GetComboBoxValueCount(__in DWORD dwFieldID,
        __out DWORD* pcItems, __out_range(<, *pcItems) DWORD* pdwSelectedItem);
    IFACEMETHODIMP GetComboBoxValueAt(__in DWORD dwFieldID,
        __in DWORD dwItem, __deref_out PWSTR* ppwszItem);
    IFACEMETHODIMP GetSubmitButtonValue(__in DWORD dwFieldID,
        __out DWORD* pdwAdjacentTo);

    IFACEMETHODIMP SetStringValue(__in DWORD dwFieldID, __in PCWSTR pwz);
    IFACEMETHODIMP SetCheckboxValue(__in DWORD dwFieldID, __in BOOL bChecked);
    IFACEMETHODIMP SetComboBoxSelectedValue(__in DWORD dwFieldID,
        __in DWORD dwSelectedItem);
    IFACEMETHODIMP CommandLinkClicked(__in DWORD dwFieldID);

    IFACEMETHODIMP GetSerialization(
        __out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
        __out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
        __deref_out_opt PWSTR* ppwszOptionalStatusText,
        __out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);
    IFACEMETHODIMP ReportResult(__in NTSTATUS ntsStatus,
        __in NTSTATUS ntsSubstatus,
        __deref_out_opt PWSTR* ppwszOptionalStatusText,
        __out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);

    // IConnectableCredentialProviderCredential
    IFACEMETHODIMP Connect(__in IQueryContinueWithStatus* pqcws);
    IFACEMETHODIMP Disconnect();

    CCredential(std::shared_ptr<Configuration> c);
    virtual ~CCredential();

    HRESULT Initialize(
        __in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
        __in const FIELD_STATE_PAIR* rgfsp,
        __in_opt PWSTR user_name,
        __in_opt PWSTR domain_name,
        __in_opt PWSTR password);

private:
    void ShowErrorMessage(const std::wstring& message);
    void ReadFieldValues();
    void SetScenario(TOTP_SCENARIO scenario);
    void SetFieldStatePairBatch(const FIELD_STATE_PAIR* pFSP);
    std::wstring GetCleanUsername();

    LONG                                    _cRef;
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR    _rgCredProvFieldDescriptors[FID_NUM_FIELDS];
    FIELD_STATE_PAIR                        _rgFieldStatePairs[FID_NUM_FIELDS];
    wchar_t*                                _rgFieldStrings[FID_NUM_FIELDS];
    ICredentialProviderCredentialEvents*     _pCredProvCredentialEvents;

    std::shared_ptr<Configuration>          _config;
    bool                                    _authSuccess;

    // Enrollment state
    HBITMAP                                 _hQRBitmap;
    std::vector<uint8_t>                    _enrollmentSecret;
    std::string                             _enrollmentBase32;
};
