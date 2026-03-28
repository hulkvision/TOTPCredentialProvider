/* TOTP Credential Provider Filter
 * Dll.h - DLL globals
 */

#pragma once

#include <windows.h>
#include <unknwn.h>

extern HINSTANCE g_hinst;
#define HINST_THISDLL g_hinst

void DllAddRef() noexcept;
void DllRelease() noexcept;
