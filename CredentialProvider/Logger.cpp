/* TOTP Credential Provider
 * Logger.cpp — File-based debug logging implementation
 *
 * Writes timestamped log lines to C:\totp-credential-provider.log.
 * Logging is disabled by default; enable via registry key "release_log" = 1.
 *
 * Copyright 2026 — Apache License, Version 2.0
 */

#include "Logger.h"
#include <fstream>
#include <ctime>
#include <sstream>
#include <iomanip>

Logger& Logger::Get()
{
    static Logger instance;
    return instance;
}

void Logger::WriteToFile(const wchar_t* message)
{
    if (!enabled) return;

    std::wofstream file(TOTP_LOG_FILE, std::ios::app);
    if (file.is_open())
    {
        // Timestamp
        SYSTEMTIME st;
        GetLocalTime(&st);
        wchar_t timestamp[64];
        swprintf_s(timestamp, L"%04d-%02d-%02d %02d:%02d:%02d.%03d",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

        file << timestamp << L" | " << message << std::endl;
        file.close();
    }
}

void Logger::Log(const char* message)
{
    if (!enabled || !message) return;
    int len = MultiByteToWideChar(CP_ACP, 0, message, -1, nullptr, 0);
    if (len > 0)
    {
        std::wstring wmsg(len - 1, 0);
        MultiByteToWideChar(CP_ACP, 0, message, -1, &wmsg[0], len);
        WriteToFile(wmsg.c_str());
    }
}

void Logger::Log(const wchar_t* message)
{
    if (!enabled || !message) return;
    WriteToFile(message);
}

void Logger::Log(const std::string& message)
{
    Log(message.c_str());
}

void Logger::Log(const std::wstring& message)
{
    Log(message.c_str());
}

void Logger::Log(const char* function, const char* message)
{
    if (!enabled) return;
    std::string combined = std::string(function) + ": " + message;
    Log(combined);
}

void Logger::Log(const char* function, const std::wstring& message)
{
    if (!enabled) return;
    int len = MultiByteToWideChar(CP_ACP, 0, function, -1, nullptr, 0);
    std::wstring wfunc(len - 1, 0);
    MultiByteToWideChar(CP_ACP, 0, function, -1, &wfunc[0], len);
    std::wstring combined = wfunc + L": " + message;
    WriteToFile(combined.c_str());
}

void Logger::Log(HRESULT hr)
{
    if (!enabled) return;
    std::wstring msg = L"HRESULT: 0x" + std::to_wstring(hr);
    WriteToFile(msg.c_str());
}
