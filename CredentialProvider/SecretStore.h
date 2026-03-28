/* TOTP Credential Provider
 * SecretStore.h — DPAPI-encrypted per-user TOTP secret storage
 *
 * Stores TOTP secrets in a protected HKLM registry key.
 * Each user gets their own subkey identified by SID.
 * Secrets are encrypted using DPAPI (machine scope).
 *
 * Copyright 2026 — Apache License, Version 2.0
 */

#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <windows.h>

class SecretStore
{
public:
    // Registry base path for secret storage
    static const std::wstring registryBasePath;

    // Check if a TOTP secret exists for the given user SID
    static bool HasSecret(const std::wstring& userSID);

    // Check if the user has completed enrollment
    static bool IsEnrolled(const std::wstring& userSID);

    // Get the decrypted TOTP secret for the given user SID
    // Returns empty vector if not found or decryption fails
    static std::vector<uint8_t> GetSecret(const std::wstring& userSID);

    // Store an encrypted TOTP secret for the given user SID
    static HRESULT StoreSecret(const std::wstring& userSID,
        const std::vector<uint8_t>& secret);

    // Mark the user as enrolled (TOTP setup completed)
    static HRESULT MarkEnrolled(const std::wstring& userSID);

    // Delete a user's TOTP secret (for admin reset)
    static HRESULT DeleteSecret(const std::wstring& userSID);

    // Get the SID string for a given username
    static std::wstring GetUserSID(const std::wstring& username);

private:
    // DPAPI encryption/decryption
    static std::vector<uint8_t> EncryptData(const std::vector<uint8_t>& plaintext);
    static std::vector<uint8_t> DecryptData(const std::vector<uint8_t>& ciphertext);

    // Get the full registry path for a user SID
    static std::wstring GetUserKeyPath(const std::wstring& userSID);
};
