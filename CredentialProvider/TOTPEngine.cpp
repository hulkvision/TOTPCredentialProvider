/* TOTP Credential Provider
 * TOTPEngine.cpp — TOTP generation/validation implementation (RFC 6238)
 *
 * Uses Windows BCrypt API for HMAC-SHA1 computation.
 * Uses BCryptGenRandom for cryptographic secret generation.
 *
 * Reference: RFC 6238 (TOTP), RFC 4226 (HOTP), RFC 4648 (Base32)
 *
 * Copyright 2026 — Apache License, Version 2.0
 */

#include "TOTPEngine.h"
#include "Logger.h"

#include <bcrypt.h>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <algorithm>

#pragma comment(lib, "bcrypt.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// ---------------------------------------------------------------------------
// GenerateSecret — Produce N cryptographically random bytes
// ---------------------------------------------------------------------------
std::vector<uint8_t> TOTPEngine::GenerateSecret(int numBytes)
{
    std::vector<uint8_t> secret(numBytes);

    NTSTATUS status = BCryptGenRandom(
        nullptr,
        secret.data(),
        static_cast<ULONG>(secret.size()),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if (!NT_SUCCESS(status))
    {
        DebugPrint("BCryptGenRandom failed!");
        // Fallback: zero-filled (this should never happen on a healthy system)
        std::fill(secret.begin(), secret.end(), 0);
    }

    return secret;
}

// ---------------------------------------------------------------------------
// HMAC_SHA1 — Compute HMAC-SHA1 using Windows BCrypt API
// ---------------------------------------------------------------------------
std::vector<uint8_t> TOTPEngine::HMAC_SHA1(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& message)
{
    std::vector<uint8_t> result(20); // SHA1 = 20 bytes

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS status;

    // Open HMAC-SHA1 algorithm
    status = BCryptOpenAlgorithmProvider(
        &hAlg, BCRYPT_SHA1_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(status))
    {
        DebugPrint("BCryptOpenAlgorithmProvider failed for HMAC-SHA1");
        return result;
    }

    // Create hash with HMAC key
    status = BCryptCreateHash(
        hAlg, &hHash,
        nullptr, 0,
        const_cast<PUCHAR>(key.data()),
        static_cast<ULONG>(key.size()),
        0);
    if (!NT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        DebugPrint("BCryptCreateHash failed");
        return result;
    }

    // Hash the message data
    status = BCryptHashData(
        hHash,
        const_cast<PUCHAR>(message.data()),
        static_cast<ULONG>(message.size()),
        0);
    if (!NT_SUCCESS(status))
    {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        DebugPrint("BCryptHashData failed");
        return result;
    }

    // Finish and retrieve the HMAC result
    status = BCryptFinishHash(hHash, result.data(), static_cast<ULONG>(result.size()), 0);
    if (!NT_SUCCESS(status))
    {
        DebugPrint("BCryptFinishHash failed");
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return result;
}

// ---------------------------------------------------------------------------
// DynamicTruncate — RFC 4226 Section 5.4
// ---------------------------------------------------------------------------
uint32_t TOTPEngine::DynamicTruncate(const std::vector<uint8_t>& hmacResult)
{
    if (hmacResult.size() < 20) return 0;

    // Use the last nibble of the HMAC as offset
    int offset = hmacResult[19] & 0x0F;

    // Extract 4 bytes from the offset, mask the top bit
    uint32_t code =
        (static_cast<uint32_t>(hmacResult[offset] & 0x7F) << 24) |
        (static_cast<uint32_t>(hmacResult[offset + 1] & 0xFF) << 16) |
        (static_cast<uint32_t>(hmacResult[offset + 2] & 0xFF) << 8) |
        (static_cast<uint32_t>(hmacResult[offset + 3] & 0xFF));

    return code;
}

// ---------------------------------------------------------------------------
// GenerateCode — Produce a TOTP code for the given secret and time
// ---------------------------------------------------------------------------
std::string TOTPEngine::GenerateCode(
    const std::vector<uint8_t>& secret,
    int digits,
    int period,
    int64_t timeOverride)
{
    // Get current Unix time or use override
    int64_t currentTime;
    if (timeOverride >= 0)
    {
        currentTime = timeOverride;
    }
    else
    {
        currentTime = static_cast<int64_t>(std::time(nullptr));
    }

    // Calculate time step counter (T)
    int64_t counter = currentTime / period;

    // Encode counter as 8-byte big-endian
    std::vector<uint8_t> counterBytes(8);
    for (int i = 7; i >= 0; --i)
    {
        counterBytes[i] = static_cast<uint8_t>(counter & 0xFF);
        counter >>= 8;
    }

    // Compute HMAC-SHA1
    std::vector<uint8_t> hmac = HMAC_SHA1(secret, counterBytes);

    // Dynamic truncation
    uint32_t truncated = DynamicTruncate(hmac);

    // Modulo to get the desired number of digits
    uint32_t modulo = 1;
    for (int i = 0; i < digits; ++i) modulo *= 10;
    uint32_t otp = truncated % modulo;

    // Format with leading zeros
    std::ostringstream oss;
    oss << std::setw(digits) << std::setfill('0') << otp;
    return oss.str();
}

// ---------------------------------------------------------------------------
// ValidateCode — Check OTP with tolerance window
// ---------------------------------------------------------------------------
bool TOTPEngine::ValidateCode(
    const std::vector<uint8_t>& secret,
    const std::string& code,
    int digits,
    int period,
    int window)
{
    if (code.length() != static_cast<size_t>(digits))
        return false;

    int64_t currentTime = static_cast<int64_t>(std::time(nullptr));

    // Check the current step and ±window steps
    for (int i = -window; i <= window; ++i)
    {
        int64_t checkTime = currentTime + (static_cast<int64_t>(i) * period);
        std::string expected = GenerateCode(secret, digits, period, checkTime);
        if (expected == code)
            return true;
    }

    return false;
}

// ---------------------------------------------------------------------------
// Base32 Encode (RFC 4648)
// ---------------------------------------------------------------------------
std::string TOTPEngine::Base32Encode(const std::vector<uint8_t>& data)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string result;
    result.reserve((data.size() * 8 + 4) / 5);

    int buffer = 0;
    int bitsLeft = 0;

    for (uint8_t byte : data)
    {
        buffer = (buffer << 8) | byte;
        bitsLeft += 8;

        while (bitsLeft >= 5)
        {
            bitsLeft -= 5;
            result += alphabet[(buffer >> bitsLeft) & 0x1F];
        }
    }

    // Handle remaining bits
    if (bitsLeft > 0)
    {
        buffer <<= (5 - bitsLeft);
        result += alphabet[buffer & 0x1F];
    }

    return result;
}

// ---------------------------------------------------------------------------
// Base32 Decode (RFC 4648)
// ---------------------------------------------------------------------------
std::vector<uint8_t> TOTPEngine::Base32Decode(const std::string& encoded)
{
    std::vector<uint8_t> result;
    int buffer = 0;
    int bitsLeft = 0;

    for (char c : encoded)
    {
        // Skip padding and whitespace
        if (c == '=' || c == ' ' || c == '\n' || c == '\r')
            continue;

        int val;
        if (c >= 'A' && c <= 'Z')
            val = c - 'A';
        else if (c >= 'a' && c <= 'z')
            val = c - 'a';
        else if (c >= '2' && c <= '7')
            val = c - '2' + 26;
        else
            continue; // Skip invalid characters

        buffer = (buffer << 5) | val;
        bitsLeft += 5;

        if (bitsLeft >= 8)
        {
            bitsLeft -= 8;
            result.push_back(static_cast<uint8_t>((buffer >> bitsLeft) & 0xFF));
        }
    }

    return result;
}

// ---------------------------------------------------------------------------
// BuildOTPAuthURI — Generate otpauth:// URI for QR code
// ---------------------------------------------------------------------------
std::string TOTPEngine::BuildOTPAuthURI(
    const std::string& base32Secret,
    const std::string& username,
    const std::string& issuer,
    int digits,
    int period)
{
    // otpauth://totp/Issuer:username?secret=XXX&issuer=Issuer&digits=6&period=30
    std::ostringstream oss;
    oss << "otpauth://totp/";

    // URL-encode the issuer and username (simplified: just replace spaces)
    std::string safeIssuer = issuer;
    std::string safeUsername = username;
    // Simple percent encoding for common chars
    auto urlEncode = [](std::string& s) {
        std::string result;
        for (char c : s)
        {
            if (c == ' ') result += "%20";
            else if (c == '@') result += "%40";
            else if (c == ':') result += "%3A";
            else result += c;
        }
        s = result;
    };
    urlEncode(safeIssuer);
    urlEncode(safeUsername);

    oss << safeIssuer << ":" << safeUsername;
    oss << "?secret=" << base32Secret;
    oss << "&issuer=" << safeIssuer;
    oss << "&digits=" << digits;
    oss << "&period=" << period;
    oss << "&algorithm=SHA1";

    return oss.str();
}

// ---------------------------------------------------------------------------
// String conversion helpers
// ---------------------------------------------------------------------------
std::string TOTPEngine::WideToUTF8(const std::wstring& wstr)
{
    if (wstr.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string result(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], size, nullptr, nullptr);
    return result;
}

std::wstring TOTPEngine::UTF8ToWide(const std::string& str)
{
    if (str.empty()) return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    std::wstring result(size - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &result[0], size);
    return result;
}
