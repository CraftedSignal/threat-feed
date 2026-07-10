---
title: CVE-2026-12595 - Authentication Bypass in LoginPress Pro WordPress Plugin via Unverified OAuth Email
slug: 2026-07-loginpress-pro-auth-bypass
description: The LoginPress Pro plugin for WordPress, in versions up to and including 6.2.3, is vulnerable to an Authentication Bypass (CVE-2026-12595) due to its Discord OAuth callback handler accepting an email field from Discord's `/users/@me` endpoint without verifying the profile's 'verified' flag, which allows unauthenticated attackers to map an unverified Discord email to an existing WordPress account, including administrator accounts, and gain an authenticated session, leading to account takeover.
date: "2026-07-10T00:18:27Z"
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
  - cve
  - account-takeover
vendors:
  - LoginPress
products:
  - LoginPress Pro plugin (<= 6.2.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: This makes it possible for unauthenticated attackers to take over any existing WordPress account — including administrator accounts — by registering a Discord account configured with an unverified email address that matches the target user's registered WordPress email and completing the standard Discord OAuth flow.
    confidence_band: high
cves:
  - id: CVE-2026-12595
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12595
---

A critical authentication bypass vulnerability, identified as CVE-2026-12595, has been discovered in the LoginPress Pro plugin for WordPress, affecting all versions up to and including 6.2.3. This flaw resides within the `loginpress_on_discord_login()` Discord OAuth callback handler. The plugin processes user profile information returned by Discord's `/users/@me` endpoint but crucially fails to check the `verified` flag for the email address provided. Instead, it directly maps the supplied email to a local WordPress account using `get_user_by('email', $profile['email'])` and subsequently issues an authenticated session cookie via `wp_set_auth_cookie()`. This oversight allows unauthenticated attackers to assume control of any WordPress account, including those with administrative privileges, by simply registering a Discord account with an unverified email address that matches the target WordPress user's registered email, then completing the standard Discord OAuth flow on the vulnerable WordPress site. The vulnerability has a CVSS v3.1 Base Score of 8.1, indicating high severity.

## Attack Chain

1. An unauthenticated attacker registers a new Discord account, configuring it with an email address that precisely matches the email of a target WordPress user on the vulnerable site.
2. The attacker navigates to the target WordPress site's login page and initiates the Discord OAuth login flow, redirecting to Discord for authentication.
3. The attacker authenticates to Discord using their newly created account with the matching, but unverified, email address.
4. Discord redirects the attacker's browser back to the WordPress site's LoginPress Pro plugin's Discord OAuth callback handler (e.g., `/wp-json/loginpress/v1/auth/discord/callback`), sending the Discord user's profile data, including the unverified email.
5. The LoginPress Pro plugin, specifically the `loginpress_on_discord_login()` function, receives this callback and, without verifying the email's 'verified' status, uses `get_user_by('email', $profile['email'])` to locate a corresponding WordPress account.
6. The plugin successfully identifies the target WordPress account based on the matching email and proceeds to issue an authenticated session cookie to the attacker via `wp_set_auth_cookie()`.
7. The attacker's browser receives the authenticated session cookie, granting them full unauthorized access and control over the targeted WordPress account, including administrator accounts.

## Impact

Successful exploitation of CVE-2026-12595 leads directly to full account takeover for any user on the affected WordPress site, including critical administrator accounts. Attackers can leverage this access to deface websites, inject malicious code, steal sensitive data, create new administrative users, or completely compromise the WordPress instance. The broad applicability of this vulnerability to any WordPress account whose email matches an attacker-controlled Discord account means that all users are at risk. Given the CVSS v3.1 Base Score of 8.1, the potential damage and ease of exploitation are significant.

## Recommendation

* Immediately update the LoginPress Pro plugin to a patched version (6.2.4 or higher) to remediate CVE-2026-12595.
* Review web server access logs for repeated or unusual access patterns to the Discord OAuth callback endpoint (e.g., `/wp-json/loginpress/v1/auth/discord/callback`) that might indicate attempted exploitation of CVE-2026-12595 prior to patching.
* Scrutinize WordPress audit logs for unexpected administrative login events, especially those that occurred shortly after the plugin was exploited for CVE-2026-12595.
