---
title: Authentication Bypass in VentraConnect Passwordless Login Plugin
slug: 2026-08-ventraconnect-auth-bypass
description: An authentication bypass vulnerability in the VentraConnect WordPress plugin allows unauthenticated attackers to hijack user accounts, including administrators, by spoofing verified email claims during Spotify OAuth flows.
date: "2026-08-12T03:55:10Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - VentraConnect
products:
  - Social Login, Passkeys, Magic Link & Email OTP – Passwordless Login (<= 1.4.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: An attacker can use a controlled Spotify account to provide an arbitrary target email address; the plugin incorrectly trusts this input as proof of mailbox ownership.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: User_Links::link_or_login_user() subsequently passes it directly to get_user_by('email', $email) and issues a persistent authentication cookie.
    confidence_band: high
cves:
  - id: CVE-2026-18961
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18961
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade VentraConnect plugin to version > 1.4.3 or disable Spotify social login
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-18961 mandates plugin update
---

The VentraConnect 'Social Login, Passkeys, Magic Link & Email OTP' plugin for WordPress (all versions up to and including 1.4.3) contains a critical authentication bypass vulnerability identified as CVE-2026-18961. The vulnerability stems from improper validation of OAuth responses from the Spotify API. Specifically, the plugin's `Generic::normalize_common()` method consumes the email field from the Spotify `/v1/me` endpoint without verifying the associated `email_verified` claim. The subsequent `User_Links::link_or_login_user()` method uses this unverified email to identify and log in WordPress users via `wp_set_auth_cookie()` without requiring an additional ownership challenge or provider-side verification gate. An attacker can create a Spotify account with a target victim's email address and leverage the OAuth flow to masquerade as the target user, effectively gaining unauthorized access to the WordPress site. If the target is an Administrator, the attacker gains full site control.

## Impact

Successful exploitation allows for complete site takeover. By targeting the email addresses of site administrators, an attacker can bypass all authentication mechanisms to gain administrative privileges. This vulnerability exposes affected websites to full administrative compromise, data exfiltration, and persistent backdooring, as the WordPress ecosystem often ties authentication to site-wide configuration and content management.

## Recommendation

* Update the 'Social Login, Passkeys, Magic Link & Email OTP' plugin to a version released after 1.4.3 immediately.
* If an update is not available, disable the Spotify social login integration within the plugin settings until a patch is applied.
* Review WordPress user account activity and session logs for unusual login patterns or modifications to administrative account profiles occurring during the period the plugin was active and unpatched.
