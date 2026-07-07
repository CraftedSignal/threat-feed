---
title: Coder OIDC Account Takeover Vulnerabilities (CVE-2026-55075)
slug: 2026-07-coder-oidc-at
description: Two critical flaws in Coder's OIDC login mechanism, CVE-2026-55075, allow an attacker to achieve account takeover by exploiting email-based user matching without proper IdP subject checks and bypassing the `email_verified` claim, leading to full access to victim workspaces and resources.
date: "2026-07-06T20:57:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - oidc
  - account-takeover
  - vulnerability
  - coder
  - cloud
vendors:
  - Coder
products:
  - Coder < 2.29.17
  - Coder >= 2.30.0, < 2.32.7
  - Coder >= 2.33.0, < 2.33.8
  - Coder >= 2.34.0, < 2.34.2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: An attacker who could authenticate at the configured OIDC provider with an email matching a victim's Coder account could log in as that victim and gain full access.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: An attacker who could authenticate at the configured OIDC provider with an email matching a victim's Coder account could log in as that victim and gain full access to their workspaces, templates and resources.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-9r87-mvcw-x35f
---

CVE-2026-55075 describes two critical vulnerabilities discovered in Coder's OpenID Connect (OIDC) login process, publicly disclosed in July 2026 by Anthropic's Security Team. The first flaw involves email-based user matching, which would link a Coder account to an OIDC identity based solely on a matching email address, even if an existing link to a different Identity Provider (IdP) subject was present. The second flaw permits bypassing the `email_verified` claim, where the system incorrectly treated an absent or non-boolean `email_verified` claim as verified. Chaining these issues allows an attacker controlling a matching email address at the OIDC provider to log in as a victim Coder user, gaining full access to their development workspaces, templates, and resources. This vulnerability specifically targets Coder installations configured with OIDC authentication, affecting versions prior to `v2.29.17` and specific ranges within the `2.30.x`, `2.33.x`, and `2.34.x` series.

## Attack Chain

1.  Attacker identifies a Coder instance configured to use OIDC authentication.
2.  Attacker discovers a victim's email address registered with a Coder account on the target instance.
3.  Attacker registers or takes control of an account at the configured OIDC provider using the victim's email address.
4.  Attacker initiates an OIDC login flow to the vulnerable Coder instance, authenticating via their controlled OIDC provider account.
5.  The OIDC provider issues an ID Token to the attacker, where the `email_verified` claim is either absent or has a non-boolean value.
6.  The vulnerable Coder instance processes the ID Token, but due to CVE-2026-55075, it bypasses the `email_verified` check and performs user matching based solely on the email address.
7.  The Coder instance incorrectly links the attacker's OIDC identity to the victim's existing Coder account.
8.  The attacker is granted full access to the victim's Coder account, including workspaces, templates, and resources.

## Impact

Successful exploitation of CVE-2026-55075 leads to complete account takeover within the affected Coder environment. An attacker gains full administrative access to the victim's Coder workspaces, templates, and any associated resources, including access to sensitive code, development environments, and potentially integrated systems. This could lead to data exfiltration, intellectual property theft, code manipulation, or further lateral movement within an organization's development infrastructure. The prerequisites for this attack include the use of OIDC authentication, the attacker's ability to control an email address at the IdP matching the victim's Coder account, and the victim's account not already being linked to a different IdP subject.

## Recommendation

*   Immediately patch all Coder installations to the recommended versions to address CVE-2026-55075: `v2.34.2`, `v2.33.8`, `v2.32.7`, or `v2.29.17`.
*   As a temporary workaround for CVE-2026-55075, configure your OIDC provider to disallow self-registration of user accounts.
*   As an additional temporary workaround for CVE-2026-55075, ensure your OIDC provider is configured to strictly require email verification before issuing ID Tokens for user accounts.
