/* TOTP Credential Provider
 * Logger.h — Simple file-based debug logging
 *
 * Copyright 2026 — Apache License, Version 2.0
 */

#pragma once

#include <string>
#include <windows.h>

#define TOTP_LOG_FILE L"C:\\totp-credential-provider.log"

class Logger
{
public:
    static Logger& Get();

    void Log(const char* message);
    void Log(const wchar_t* message);
    void Log(const std::string& message);
    void Log(const std::wstring& message);
    void Log(const char* function, const char* message);
    void Log(const char* function, const std::wstring& message);
    void Log(HRESULT hr);

    bool enabled = false;

private:
    Logger() = default;
    void WriteToFile(const wchar_t* message);
};

// Convenience macros
#define DebugPrint(msg) Logger::Get().Log(msg)
#define DebugPrintFunction(msg) Logger::Get().Log(__FUNCTION__, msg)
