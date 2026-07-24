---
title: Account Takeover via Pre-Account Hijacking in Better Auth Library
slug: 2026-07-account-takeover-magic-link-otp
description: An attacker can perform a pre-account hijacking attack against the `better-auth` library if it uses magic-link or email-OTP plugins alongside open email and password registration and allows unverified accounts. The attacker first registers an account using the victim's email with a password they control. When the legitimate victim later uses a passwordless flow to verify their account, the attacker's pre-set password remains active, granting them persistent, unauthorized access to the victim's account and data, potentially leading to account takeover and user lockout.
date: "2026-07-24T15:45:24Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - account-takeover
  - vulnerability
  - web-application
  - pre-account-hijacking
products:
  - better-auth < 1.6.22
  - better-auth 1.7.0-beta < 1.7.0-beta.10
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1136
    technique_name: Create Account
    evidence: First, with open registration, the attacker signs up using the victim's email and a password the attacker picks.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: So a password set before anyone proved control of the mailbox kept working after the owner proved control.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: That step marks the account verified, and the attacker's password now works on it.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-qq9h-g4jm-xgf3
---

A high-severity pre-account hijacking vulnerability has been identified in the `better-auth` library, affecting versions below 1.6.22 and 1.7.0-beta below 1.7.0-beta.10. This flaw enables an attacker to gain and maintain persistent access to a victim's account. The attack targets configurations where the library uses magic-link or email-OTP plugins, alongside open email and password registration, allowing unverified accounts to exist. The core issue lies in the library's failure to remove an attacker-set password or revoke existing sessions when a legitimate user later verifies an account via a passwordless flow that was initially "claimed" by the attacker. This can lead to unauthorized access to personal data, account manipulation, and potential lockout of the legitimate user. The vulnerability is comparable to other pre-account hijacking issues and highlights the importance of authoritative control over email addresses during account verification.

## Attack Chain

1. The attacker, leveraging open registration, signs up for an account using the victim's email address and a password of their choice. The account remains unverified at this stage.
2. The legitimate victim later attempts to sign in or verify their account using a passwordless flow, such as a magic link or an email One-Time Password (OTP).
3. The `better-auth` library processes the victim's legitimate passwordless sign-in, marking the pre-existing account as verified and issuing a new session for the victim.
4. Due to the vulnerability, the attacker's pre-set password for the victim's email address is not removed, nor are any existing sessions created by the attacker revoked.
5. The attacker uses their previously chosen password to log into the victim's now-verified account.
6. The attacker gains persistent, unauthorized access to the victim's account, potentially reading data, making changes, or initiating a credential reset to lock the victim out.

## Impact

If successfully exploited, this vulnerability grants an attacker lasting password access to an account that the victim depends on, effectively alongside the legitimate user. This unauthorized access allows the attacker to view, modify, or exfiltrate the victim's data. Furthermore, the attacker could reset the account credentials, leading to a complete lockout of the legitimate account owner. The attack requires a specific configuration of `better-auth` that includes open email and password sign-up paired with passwordless flows like magic links or email OTPs.

## Recommendation

* Upgrade the `better-auth` library to version 1.6.22 or later on the stable line, or to version 1.7.0-beta.10 or later on the pre-release line, to patch the vulnerability.
* If immediate upgrade is not possible, implement application-level controls to require email verification before accepting any password on an account.
* Implement application logic to quickly remove unverified accounts to reduce the window of opportunity for pre-account hijacking.
