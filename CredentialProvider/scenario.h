/* TOTP Credential Provider
 * scenario.h — Field definitions and display state pairs
 *
 * Defines the UI fields shown on the Windows login tile and their
 * visibility states for each login scenario (enrollment, password, OTP).
 *
 * Copyright 2026 — Apache License, Version 2.0
 */

#pragma once

#include <credentialprovider.h>

// ---------------------------------------------------------------------------
// Field IDs — each field in the credential tile
// ---------------------------------------------------------------------------
enum FIELD_ID
{
    FID_LOGO          = 0,   // Main tile image (128x128 BMP)
    FID_LARGE_TEXT    = 1,   // Title text ("TOTP Login")
    FID_SMALL_TEXT    = 2,   // Status/hint text
    FID_USERNAME      = 3,   // Username input
    FID_LDAP_PASS     = 4,   // Password input
    FID_OTP           = 5,   // OTP code input
    FID_QR_IMAGE      = 6,   // QR code bitmap (shown during enrollment)
    FID_SUBMIT_BUTTON = 7,   // Submit button
    FID_NUM_FIELDS    = 8
};

// ---------------------------------------------------------------------------
// Field state pair — visibility + interactivity for each field
// ---------------------------------------------------------------------------
struct FIELD_STATE_PAIR
{
    CREDENTIAL_PROVIDER_FIELD_STATE cpfs;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;
};

// ---------------------------------------------------------------------------
// Scenario: LOGON — Username + Password (first step)
// Shows: Logo, Title, Username, Password, Submit
// ---------------------------------------------------------------------------
static const FIELD_STATE_PAIR s_rgScenarioLogonPasswordFirst[] =
{
    { CPFS_DISPLAY_IN_BOTH,          CPFIS_NONE    },  // FID_LOGO
    { CPFS_DISPLAY_IN_BOTH,          CPFIS_NONE    },  // FID_LARGE_TEXT
    { CPFS_HIDDEN,                   CPFIS_NONE    },  // FID_SMALL_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },  // FID_USERNAME
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE    },  // FID_LDAP_PASS
    { CPFS_HIDDEN,                   CPFIS_NONE    },  // FID_OTP
    { CPFS_HIDDEN,                   CPFIS_NONE    },  // FID_QR_IMAGE
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE    },  // FID_SUBMIT_BUTTON
};

// ---------------------------------------------------------------------------
// Scenario: UNLOCK — Password only (username from session)
// Shows: Logo, Title, SmallText (username), Password, Submit
// ---------------------------------------------------------------------------
static const FIELD_STATE_PAIR s_rgScenarioUnlockPassword[] =
{
    { CPFS_DISPLAY_IN_BOTH,          CPFIS_NONE    },  // FID_LOGO
    { CPFS_DISPLAY_IN_BOTH,          CPFIS_NONE    },  // FID_LARGE_TEXT
    { CPFS_DISPLAY_IN_BOTH,          CPFIS_NONE    },  // FID_SMALL_TEXT
    { CPFS_HIDDEN,                   CPFIS_NONE    },  // FID_USERNAME
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },  // FID_LDAP_PASS
    { CPFS_HIDDEN,                   CPFIS_NONE    },  // FID_OTP
    { CPFS_HIDDEN,                   CPFIS_NONE    },  // FID_QR_IMAGE
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE    },  // FID_SUBMIT_BUTTON
};

// ---------------------------------------------------------------------------
// Scenario: OTP STEP — OTP input only (second step after password)
// Shows: Logo, Title, SmallText (hint), OTP, Submit
// ---------------------------------------------------------------------------
static const FIELD_STATE_PAIR s_rgScenarioOTPStep[] =
{
    { CPFS_DISPLAY_IN_BOTH,          CPFIS_NONE    },  // FID_LOGO
    { CPFS_DISPLAY_IN_BOTH,          CPFIS_NONE    },  // FID_LARGE_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE    },  // FID_SMALL_TEXT
    { CPFS_HIDDEN,                   CPFIS_NONE    },  // FID_USERNAME
    { CPFS_HIDDEN,                   CPFIS_NONE    },  // FID_LDAP_PASS
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },  // FID_OTP
    { CPFS_HIDDEN,                   CPFIS_NONE    },  // FID_QR_IMAGE
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE    },  // FID_SUBMIT_BUTTON
};

// ---------------------------------------------------------------------------
// Scenario: ENROLLMENT — QR code + OTP input (first-time setup)
// Shows: Logo, Title, SmallText (instructions), QR, OTP, Submit
// ---------------------------------------------------------------------------
static const FIELD_STATE_PAIR s_rgScenarioEnrollment[] =
{
    { CPFS_DISPLAY_IN_BOTH,          CPFIS_NONE    },  // FID_LOGO
    { CPFS_DISPLAY_IN_BOTH,          CPFIS_NONE    },  // FID_LARGE_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE    },  // FID_SMALL_TEXT
    { CPFS_HIDDEN,                   CPFIS_NONE    },  // FID_USERNAME
    { CPFS_HIDDEN,                   CPFIS_NONE    },  // FID_LDAP_PASS
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },  // FID_OTP
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE    },  // FID_QR_IMAGE
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE    },  // FID_SUBMIT_BUTTON
};

// ---------------------------------------------------------------------------
// Field descriptors — type and label for each field
// ---------------------------------------------------------------------------
static CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgCredProvFieldDescriptors[] =
{
    { FID_LOGO,          CPFT_TILE_IMAGE,    L"TOTP Login" },
    { FID_LARGE_TEXT,    CPFT_LARGE_TEXT,    L"TOTP Login" },
    { FID_SMALL_TEXT,    CPFT_SMALL_TEXT,    L"" },
    { FID_USERNAME,      CPFT_EDIT_TEXT,     L"Username" },
    { FID_LDAP_PASS,     CPFT_PASSWORD_TEXT, L"Password" },
    { FID_OTP,           CPFT_EDIT_TEXT,     L"One-Time Password" },
    { FID_QR_IMAGE,      CPFT_TILE_IMAGE,    L"Scan QR Code" },
    { FID_SUBMIT_BUTTON, CPFT_SUBMIT_BUTTON, L"Submit" },
};

// ---------------------------------------------------------------------------
// Scenario enum for code clarity
// ---------------------------------------------------------------------------
enum class TOTP_SCENARIO
{
    NO_CHANGE = 0,
    LOGON_PASSWORD_FIRST = 1,
    UNLOCK_PASSWORD = 2,
    OTP_STEP = 3,
    ENROLLMENT = 4,
};
