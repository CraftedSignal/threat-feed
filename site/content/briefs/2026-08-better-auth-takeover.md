---
title: Account Takeover Vulnerability in better-auth via Pre-Account Hijacking
slug: 2026-08-better-auth-takeover
description: The better-auth library is vulnerable to account takeover (CVE-2026-67327) when open email/password registration is enabled, allowing attackers to maintain persistent access after a victim authenticates via passwordless flows.
date: "2026-08-01T13:53:04Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - better-auth
products:
  - better-auth (>= 1.1.3, < 1.6.22 and >= 1.7.0-beta.0, < 1.7.0-beta.10)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1585
    technique_name: Establish Accounts
    evidence: An attacker registers an account with the victim's email address and an attacker-chosen password; the account remains unverified.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    evidence: the attacker's password remains valid, granting persistent access to the victim's account.
    confidence_band: high
cves:
  - id: CVE-2026-67327
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67327
---

The better-auth library versions 1.1.3 through 1.6.21, and specific pre-release versions 1.7.0-beta.0 through 1.7.0-beta.9, contain a critical vulnerability (CVE-2026-67327) that facilitates account takeover through pre-account hijacking. This vulnerability occurs when the application configuration has open email/password registration enabled. An attacker can preemptively register an account using a target's email address and an attacker-controlled password. While the account remains unverified at this stage, the vulnerability triggers when the legitimate user initiates a passwordless authentication flow, such as magic-link or email-OTP. Upon successful verification of the user's identity via these methods, the system marks the account as verified but fails to clear the attacker-provided credentials or invalidate existing unauthorized sessions. Consequently, the attacker retains persistent access to the account using their original password. This issue is resolved in version 1.6.22 and 1.7.0-beta.10.

## Impact

Successful exploitation allows for complete account takeover, enabling unauthorized access to user data and account functions. This flaw poses a high risk to organizations relying on better-auth for identity management, particularly those allowing open registration. If left unpatched, victims who attempt to use passwordless authentication on a pre-hijacked account will unknowingly provide attackers with continued, verified access to their sensitive information.

## Recommendation

- Upgrade the better-auth library to version 1.6.22 or 1.7.0-beta.10 or later immediately to mitigate the underlying flaw identified in CVE-2026-67327.
- Review application authentication logs for accounts where email/password registration and passwordless login flows occur sequentially from different source IP addresses or session identifiers.
- If immediate patching is not possible, disable open email/password registration in the better-auth configuration to prevent the initial account creation stage of this attack.
