/* TOTP Credential Provider
 * guid.h — Unique CLSID for this credential provider
 *
 * Copyright 2026 — Apache License, Version 2.0
 */

#ifndef _GUID_H
#define _GUID_H
#pragma once

#include <guiddef.h>

// {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
// Unique CLSID for TOTP Credential Provider — generated fresh, not reusing multiOTP's GUID
DEFINE_GUID(CLSID_TOTPCredentialProvider,
	0xa1b2c3d4, 0xe5f6, 0x7890, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90);

#endif
