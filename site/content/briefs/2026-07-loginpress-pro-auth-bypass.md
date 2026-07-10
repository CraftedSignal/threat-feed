---
title: 'CVE-2026-12598: LoginPress Pro WordPress Plugin Authentication Bypass'
slug: 2026-07-loginpress-pro-auth-bypass
description: An authentication bypass vulnerability (CVE-2026-12598) exists in the LoginPress Pro plugin for WordPress, affecting versions up to and including 6.2.3 within the Spotify Social Login addon, enabling unauthenticated attackers to log in as any existing WordPress user, including administrators, by registering a Spotify account with the target's email.
date: "2026-07-10T00:20:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - plugin
  - authentication-bypass
  - web
vendors:
  - LoginPress
  - WordPress
products:
  - LoginPress Pro plugin <= 6.2.3
  - WordPress
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: Attacker identifies a target WordPress user's email address
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: This makes it possible for unauthenticated attackers to log in as any existing WordPress user, including Administrators, by registering a Spotify account using the targeted user's email address and authenticating via the Spotify provider.
    confidence_band: high
cves:
  - id: CVE-2026-12598
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12598
---

A critical authentication bypass vulnerability, identified as CVE-2026-12598, has been discovered in the LoginPress Pro plugin for WordPress, impacting all versions up to and including 6.2.3. This flaw specifically resides within the Spotify Social Login addon, which incorrectly trusts the unverified 'email' field returned by Spotify's `/v1/me` API endpoint. The plugin's `loginpress_on_spotify_login()` function uses this untrusted email address directly with `get_user_by('email', $profile['email'])` to identify and log in an existing WordPress account, without confirming the Spotify user actually owns the email or requiring proof of ownership for the matching WordPress account. This oversight creates a severe security loophole, allowing unauthenticated attackers to impersonate and gain full control over any WordPress user account, including those with administrator privileges, by simply registering a Spotify account using the target's email address and then authenticating via the Spotify provider on the vulnerable WordPress site.

## Attack Chain

1. Attacker identifies a target WordPress user's email address on a site running the vulnerable LoginPress Pro plugin.
2. Attacker creates a new Spotify account using the target's email address.
3. Attacker navigates to the vulnerable WordPress site's login page, which offers "Login with Spotify" via the LoginPress Pro plugin.
4. Attacker initiates the "Login with Spotify" authentication flow.
5. The LoginPress Pro plugin requests user profile information, including the 'email' field, from Spotify's `/v1/me` API endpoint.
6. Spotify's API returns the profile data, including the attacker-controlled (but target's) email address, which Spotify documents as unverified.
7. The plugin's `loginpress_on_spotify_login()` function directly uses this unverified 'email' field to query for an existing WordPress user account via `get_user_by('email', $profile['email'])`.
8. Upon successfully finding a matching WordPress user account based on the email, the plugin authenticates the attacker as that WordPress user, bypassing any password verification, and granting full account access.

## Impact

The successful exploitation of CVE-2026-12598 grants an unauthenticated attacker full account takeover capabilities over any WordPress user on a vulnerable site, including administrators. This can lead to complete compromise of the WordPress site, data exfiltration, website defacement, arbitrary code execution via plugin/theme editor, and further network penetration. The vulnerability applies to any WordPress instance using the LoginPress Pro plugin with the Spotify Social Login addon enabled, posing a significant risk to the integrity and confidentiality of websites and their user data across various sectors.

## Recommendation

* Patch CVE-2026-12598 immediately by updating the LoginPress Pro plugin to a version greater than 6.2.3.
* If immediate patching of the LoginPress Pro plugin is not feasible, disable the Spotify Social Login addon within the plugin as a temporary mitigation to prevent exploitation.
* Review WordPress audit logs for any suspicious login activity, particularly for administrator accounts, especially if originating from the Spotify Social Login method after July 10, 2026.
