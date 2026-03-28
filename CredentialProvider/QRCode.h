/* TOTP Credential Provider
 * QRCode.h — QR code bitmap generation
 *
 * Minimal QR code generator that produces a Windows HBITMAP
 * suitable for display in a Credential Provider tile image field.
 *
 * Uses a self-contained QR code generation algorithm (no external libraries).
 *
 * Copyright 2026 — Apache License, Version 2.0
 */

#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <windows.h>

class QRCode
{
public:
    // Generate a QR code bitmap from a text string (e.g., otpauth:// URI)
    // Returns an HBITMAP that can be used in GetBitmapValue.
    // The caller is responsible for deleting the bitmap with DeleteObject.
    static HBITMAP GenerateBitmap(const std::string& text, int scale = 4);

    // Generate the QR code matrix (true = black module)
    static std::vector<std::vector<bool>> GenerateMatrix(const std::string& text);

private:
    // QR code internal helpers
    static std::vector<uint8_t> EncodeData(const std::string& text, int version);
    static int GetVersionForData(int dataLength);
    static int GetTotalDataCodewords(int version);
    static int GetECCodewordsPerBlock(int version);

    // Reed-Solomon error correction
    static std::vector<uint8_t> CalculateEC(const std::vector<uint8_t>& data, int ecCodewords);
    static uint8_t GF256Multiply(uint8_t a, uint8_t b);

    // Matrix operations
    static void PlaceFinderPattern(std::vector<std::vector<bool>>& matrix,
        std::vector<std::vector<bool>>& reserved, int row, int col);
    static void PlaceAlignmentPattern(std::vector<std::vector<bool>>& matrix,
        std::vector<std::vector<bool>>& reserved, int row, int col);
    static void PlaceTimingPatterns(std::vector<std::vector<bool>>& matrix,
        std::vector<std::vector<bool>>& reserved, int size);
    static void PlaceFormatInfo(std::vector<std::vector<bool>>& matrix, int size, int mask);
    static void PlaceVersionInfo(std::vector<std::vector<bool>>& matrix, int size, int version);
    static void PlaceDataBits(std::vector<std::vector<bool>>& matrix,
        const std::vector<std::vector<bool>>& reserved,
        const std::vector<uint8_t>& data, int size);

    // Masking
    static bool GetMaskBit(int mask, int row, int col);
    static void ApplyMask(std::vector<std::vector<bool>>& matrix,
        const std::vector<std::vector<bool>>& reserved, int size, int mask);
    static int EvaluatePenalty(const std::vector<std::vector<bool>>& matrix, int size);

    // Bitmap creation
    static HBITMAP CreateBitmapFromMatrix(
        const std::vector<std::vector<bool>>& matrix, int scale);
};
