---
title: Authorization Bypass in FleekDash V2 WordPress Plugin
slug: 2026-07-fleekdash-auth-bypass
description: The FleekDash V2 plugin for WordPress contains an authorization bypass vulnerability (CVE-2026-14356) that allows authenticated attackers to overwrite user credentials, including administrative accounts, leading to full site compromise.
date: "2026-07-30T07:19:51Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - WordPress
products:
  - FleekDash V2 (<= 2.6.2.2)
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14356
rules:
  - title: Detect CVE-2026-14356 Exploitation Attempt
    description: Detects exploitation of CVE-2026-14356 via POST requests to the vulnerable FleekDash registration endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-14356 is a critical authorization bypass vulnerability affecting the FleekDash V2 plugin for WordPress in all versions up to and including 2.6.2.2. The vulnerability stems from the plugin's failure to properly validate user authorization for administrative actions. This flaw allows an attacker, even one with low-level subscriber access, to modify the email address and password of any user on the platform, including site administrators. 

Defenders must be aware that the plugin includes an unauthenticated endpoint at /wp-json/fleekdash/v1/register. This endpoint allows for the auto-provisioning of subscriber-level accounts even when the WordPress 'users_can_register' setting is disabled, providing the necessary authenticated context to exploit the primary credential overwrite vulnerability. This combination allows for a complete, unauthenticated-to-administrator account takeover chain, posing a significant risk to WordPress site integrity.

## Attack Chain

1. Attacker sends a POST request to the unauthenticated /wp-json/fleekdash/v1/register endpoint to create a new subscriber-level account.
2. The FleekDash plugin auto-provisions the account and returns a valid REST nonce to the attacker.
3. Attacker uses the new subscriber credentials to authenticate with the WordPress site.
4. Attacker crafts a malicious request targeting the vulnerable plugin logic that handles user profile updates.
5. Attacker includes the required REST nonce to bypass intended authorization checks within the FleekDash plugin.
6. The plugin processes the request and overwrites the target administrator's email address and password in the database.
7. Attacker uses the newly defined administrator credentials to log in, achieving full site compromise.

## Impact

Successful exploitation allows unauthenticated attackers to escalate privileges to the administrator level. This grants them full control over the WordPress installation, enabling the injection of malicious code, redirection of traffic, exfiltration of sensitive site data, and the potential deployment of secondary payloads or ransomware across the web server infrastructure.

## Recommendation

- Immediately update the FleekDash V2 plugin to a patched version beyond 2.6.2.2.
- Monitor web server logs for suspicious POST requests targeting /wp-json/fleekdash/v1/register.
- Utilize the provided Sigma rule to detect attempts to access the vulnerable registration endpoint or perform unauthorized profile updates via the REST API.
- Audit WordPress user logs for unexpected administrative account credential changes.
