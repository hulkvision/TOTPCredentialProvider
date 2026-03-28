/* TOTP Credential Provider Filter
 * guid.h - GUID definitions for the filter and the main credential provider
 */

#ifndef _FILTER_GUID_H
#define _FILTER_GUID_H
#pragma once

#include <guiddef.h>

// {B1C2D3E4-F5A6-4B7C-8D9E-0F1A2B3C4D5E}
// GUID for the Credential Provider Filter itself
DEFINE_GUID(CLSID_TOTPCredentialProviderFilter,
    0xb1c2d3e4, 0xf5a6, 0x4b7c, 0x8d, 0x9e, 0x0f, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e);

// {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
// GUID of our main TOTP Credential Provider (must match!)
DEFINE_GUID(CLSID_TOTPCredentialProvider,
    0xa1b2c3d4, 0xe5f6, 0x7890, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90);

#endif
