/* TOTP Credential Provider
 * Dll.h — DLL global state
 *
 * Copyright 2026 — Apache License, Version 2.0
 */

#pragma once

// Must be defined before any Windows header that might pull in security.h
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif

#include <windows.h>
#include <unknwn.h>

// Global DLL HINSTANCE
extern HINSTANCE g_hinst;
#define HINST_THISDLL g_hinst

void DllAddRef() noexcept;
void DllRelease() noexcept;
