---
title: Nhost Account Takeover via OAuth Email Verification Bypass
slug: 2024-01-nhost-account-takeover
description: Nhost is vulnerable to account takeover due to improper OAuth email verification in Discord, Bitbucket, AzureAD, and EntraID providers, allowing attackers to merge an unverified OAuth identity into a victim's account.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - oauth
  - account-takeover
  - nhost
vendors:
  - Nhost
products:
  - Nhost
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1586
    technique_name: Compromise Accounts
references:
  - https://github.com/advisories/GHSA-6g38-8j4p-j3pr
rules:
  - title: Detect Discord OAuth User Profile Request
    description: Detects requests to the Discord API endpoint for retrieving user profile information, potentially indicating an OAuth flow. This can be used to monitor for unusual or suspicious OAuth activity.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    techniques:
      - T1586
    data_sources:
      - network_connection
      - windows
  - title: Detect Bitbucket Email API Request
    description: Detects network connections to Bitbucket's email API endpoint which reveals confirmed and unconfirmed emails tied to a Bitbucket user. This can be used to discover suspicious OAuth or account enumeration activity.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    techniques:
      - T1586
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Nhost is vulnerable to account takeover due to improper OAuth email verification. The vulnerability stems from Nhost automatically linking incoming OAuth identities to existing Nhost accounts when email addresses match, without properly verifying the email with the OAuth provider. Several provider adapters, including Discord, Bitbucket, AzureAD, and EntraID, fail to correctly populate the `profile.EmailVerified` field. This allows an attacker to present an email they don't own to Nhost, have the OAuth identity merged into the victim's account, and gain a fully authenticated session. The vulnerable code is located in `services/auth/go/controller/sign_in_id_token.go`. Affected Nhost versions are prior to 0.0.0-20260417112436-ec8dab3f2cf4.

## Attack Chain

1. The attacker identifies a target Nhost application that utilizes a vulnerable OAuth provider (Discord, Bitbucket, AzureAD, or EntraID).
2. The attacker creates an account on the chosen OAuth provider.
3. The attacker modifies their email address on the OAuth provider to match the email address of the victim's Nhost account. In the case of Discord, the attacker changes the email but skips the verification step.
4. The attacker initiates the "Sign in with [OAuth Provider]" flow on the target Nhost application.
5. Nhost's backend fetches the attacker's profile from the OAuth provider. Due to the vulnerability, Nhost incorrectly trusts the 'verified' status, even if the email is unverified.
6. Nhost locates the victim's account based on the matching email address.
7. Nhost links the attacker's OAuth provider identity to the victim's account in the database using the `InsertUserProvider` function.
8. Nhost generates a new session for the victim's account and provides it to the attacker, granting the attacker full access to the victim's account.

## Impact

Successful exploitation allows for full account takeover of any existing Nhost user, without requiring any interaction from the victim. The attacker can then change the account email, disable other login methods, and permanently lock out the legitimate owner. This is particularly critical in applications with admin or privileged accounts, potentially leading to significant data breaches or unauthorized access to sensitive systems. The vulnerability affects Nhost versions prior to 0.0.0-20260417112436-ec8dab3f2cf4.

## Recommendation

*   Upgrade Nhost to a version containing the fix for this vulnerability (>= 0.0.0-20260417112436-ec8dab3f2cf4).
*   Implement a controller-level guard that enforces email verification regardless of the adapter's reported `EmailVerified` status, as described in the "Defense-in-Depth Gap" section. This mitigates the risk of future vulnerabilities due to changes in OAuth provider APIs.
*   For Discord, apply the fix described in the advisory, adding the `Verified` field to the `discordUserProfile` struct and utilizing it in the `EmailVerified` assignment within the `providers/discord.go` file.
*   For Bitbucket, remove the fallback to unconfirmed emails as described in the advisory, preventing the adapter from using unverified emails in `providers/bitbucket.go`.
*   For AzureAD and EntraID, avoid falling back to `preferred_username` or UPN for account-linking email, as these fields do not prove email ownership, as documented in the advisory.
