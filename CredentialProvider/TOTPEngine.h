/* TOTP Credential Provider
 * TOTPEngine.h — TOTP generation and validation (RFC 6238)
 *
 * Pure C++ implementation using Windows BCrypt API for HMAC-SHA1.
 * No external library dependencies.
 *
 * Copyright 2026 — Apache License, Version 2.0
 */

#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <windows.h>

class TOTPEngine
{
public:
    // Generate a cryptographically random secret (20 bytes = 160 bits)
    static std::vector<uint8_t> GenerateSecret(int numBytes = 20);

    // Generate a TOTP code for the given secret and current time
    static std::string GenerateCode(
        const std::vector<uint8_t>& secret,
        int digits = 6,
        int period = 30,
        int64_t timeOverride = -1  // For testing: override current time
    );

    // Validate an OTP code with a tolerance window
    // Returns true if the code matches any step within ±window
    static bool ValidateCode(
        const std::vector<uint8_t>& secret,
        const std::string& code,
        int digits = 6,
        int period = 30,
        int window = 1
    );

    // Base32 encode/decode (RFC 4648)
    static std::string Base32Encode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> Base32Decode(const std::string& encoded);

    // Build an otpauth:// URI for QR code generation
    static std::string BuildOTPAuthURI(
        const std::string& base32Secret,
        const std::string& username,
        const std::string& issuer,
        int digits = 6,
        int period = 30
    );

    // Wide string helpers
    static std::string WideToUTF8(const std::wstring& wstr);
    static std::wstring UTF8ToWide(const std::string& str);

private:
    // HMAC-SHA1 using BCrypt
    static std::vector<uint8_t> HMAC_SHA1(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& message
    );

    // Dynamic truncation (RFC 4226 Section 5.4)
    static uint32_t DynamicTruncate(const std::vector<uint8_t>& hmacResult);
};
