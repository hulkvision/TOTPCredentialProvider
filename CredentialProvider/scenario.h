/* TOTP Credential Provider
 * scenario.h — Field definitions and display state pairs
 *
 * Defines the UI fields shown on the Windows login tile and their
 * visibility states for each login scenario (enrollment, password, OTP).
 *
 * Copyright 2026 - Apache License, Version 2.0
 */

#pragma once

#include <credentialprovider.h>

// ---------------------------------------------------------------------------
// Field IDs — each field in the credential tile
// ---------------------------------------------------------------------------
enum FIELD_ID
{
    FID_LOGO          = 0,   // Main tile image (128x128 BMP) - also used for QR
    FID_LARGE_TEXT    = 1,   // Title text ("TOTP Login")
    FID_SMALL_TEXT    = 2,   // Status/hint text
    FID_USERNAME      = 3,   // Username input
    FID_LDAP_PASS     = 4,   // Password input
    FID_OTP           = 5,   // OTP code input
    FID_SUBMIT_BUTTON = 6,   // Submit button
    FID_NUM_FIELDS    = 7
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
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE    },  // FID_SUBMIT_BUTTON
};

// ---------------------------------------------------------------------------
// Scenario: ENROLLMENT — QR code shown as tile + OTP input (first-time setup)
// The QR code replaces the logo image during enrollment
// Shows: Logo/QR, Title, SmallText (instructions), OTP, Submit
// ---------------------------------------------------------------------------
static const FIELD_STATE_PAIR s_rgScenarioEnrollment[] =
{
    { CPFS_DISPLAY_IN_BOTH,          CPFIS_NONE    },  // FID_LOGO (shows QR)
    { CPFS_DISPLAY_IN_BOTH,          CPFIS_NONE    },  // FID_LARGE_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE    },  // FID_SMALL_TEXT
    { CPFS_HIDDEN,                   CPFIS_NONE    },  // FID_USERNAME
    { CPFS_HIDDEN,                   CPFIS_NONE    },  // FID_LDAP_PASS
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },  // FID_OTP
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE    },  // FID_SUBMIT_BUTTON
};

// ---------------------------------------------------------------------------
// Field descriptors — type and label for each field
// Only ONE CPFT_TILE_IMAGE is allowed per credential provider!
// ---------------------------------------------------------------------------
static CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgCredProvFieldDescriptors[] =
{
    { FID_LOGO,          CPFT_TILE_IMAGE,    const_cast<LPWSTR>(L"TOTP Login") },
    { FID_LARGE_TEXT,    CPFT_LARGE_TEXT,    const_cast<LPWSTR>(L"TOTP Login") },
    { FID_SMALL_TEXT,    CPFT_SMALL_TEXT,    const_cast<LPWSTR>(L"") },
    { FID_USERNAME,      CPFT_EDIT_TEXT,     const_cast<LPWSTR>(L"Username") },
    { FID_LDAP_PASS,     CPFT_PASSWORD_TEXT, const_cast<LPWSTR>(L"Password") },
    { FID_OTP,           CPFT_EDIT_TEXT,     const_cast<LPWSTR>(L"One-Time Password") },
    { FID_SUBMIT_BUTTON, CPFT_SUBMIT_BUTTON, const_cast<LPWSTR>(L"Submit") },
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
