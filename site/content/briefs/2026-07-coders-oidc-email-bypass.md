---
title: Coder OIDC email_verified Type Coercion Bypass (CVE-2026-55076)
slug: 2026-07-coders-oidc-email-bypass
description: A vulnerability, CVE-2026-55076, in Coder's OpenID Connect (OIDC) authentication callback allowed an attacker to bypass email verification due to improper Go boolean type assertion of the `email_verified` claim, leading to full account takeover for existing user accounts.
date: "2026-07-06T20:58:08Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - account-takeover
  - oidc
  - vulnerability
  - web-application
vendors:
  - Coder
products:
  - Coder < 2.29.17
  - Coder >= 2.30.0 < 2.32.7
  - Coder >= 2.33.0 < 2.33.8
  - Coder >= 2.34.0 < 2.34.2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A vulnerability in Coder's OIDC callback checked `email_verified` with a direct Go `bool` type assertion... This enabled account takeover.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: An attacker who registered a victim's email at a compatible IdP without verifying it could log in via OIDC and be matched to the victim's existing Coder account, receiving a session for that account.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: When an IdP returned the claim as a non-boolean (for example the string 'false') or omitted it, the assertion failed open and the email was treated as verified.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-75vm-6w67-gwvp
  - https://github.com/coder/coder/releases/tag/v2.34.2
  - https://github.com/coder/coder/releases/tag/v2.33.8
  - https://github.com/coder/coder/releases/tag/v2.32.7
  - https://github.com/coder/coder/releases/tag/v2.29.17
  - CVE-2026-55076
---

A critical vulnerability, tracked as CVE-2026-55076, has been identified in Coder's platform, affecting versions prior to 2.34.2, 2.33.8, 2.32.7, and 2.29.17. The flaw resides in how Coder's OpenID Connect (OIDC) callback processes the `email_verified` claim from an Identity Provider (IdP). Instead of robust type coercion, Coder used a direct Go `bool` type assertion. This meant that if an IdP returned `email_verified` as a non-boolean value (e.g., the string `"false"`) or omitted the claim entirely, Coder's system would incorrectly default to treating the email as verified. This misinterpretation, combined with an unconditional email-based account fallback feature, created a pathway for unauthenticated account takeover, enabling attackers to gain full control over a victim's existing Coder account without requiring prior authentication.

## Attack Chain

1.  **Initial Account Registration**: The victim legitimately registers and creates an account on a Coder instance, likely linked to their corporate email address.
2.  **Attacker IdP Setup**: The attacker registers an OpenID Connect (OIDC) Identity Provider (IdP) and configures it to impersonate the victim's email address.
3.  **IdP Claim Manipulation**: The attacker's IdP is configured to either omit the `email_verified` claim or return it as a non-boolean string (e.g., `"false"`) during an authentication response.
4.  **OIDC Authentication Attempt**: The attacker initiates an OIDC login attempt to the target Coder instance, selecting their malicious IdP.
5.  **Type Coercion Bypass**: Coder's OIDC callback receives the IdP response and, due to the vulnerability, incorrectly processes the `email_verified` claim (or its absence) as verified.
6.  **Account Fallback Activation**: Coder's unconditional email-based account fallback mechanism matches the (falsely) verified email from the IdP to the victim's existing Coder account.
7.  **Session Establishment**: Coder grants the attacker a valid session for the victim's account, resulting in a full account takeover.

## Impact

Successful exploitation of CVE-2026-55076 allows for complete account takeover of any existing Coder user. An attacker does not need prior authentication to the Coder instance. This means sensitive data, project code, and system configurations associated with the compromised account become fully accessible to the attacker. While no specific victim count or targeted sector is provided, Coder is widely used for development environments, meaning a wide range of organizations and intellectual property could be at risk. The direct result is unauthorized access to development infrastructure and potential lateral movement within an organization's ecosystem.

## Recommendation

*   **Patch CVE-2026-55076 immediately** by upgrading your Coder instance to version 2.34.2, 2.33.8, 2.32.7, or 2.29.17 as described in the brief.
*   **Review IdP configurations**: Ensure your Identity Provider (IdP) for OIDC returns the `email_verified` claim as a native JSON boolean (`true` or `false`) to mitigate risks in case of other application vulnerabilities.
