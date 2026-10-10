---
title: Authentication Bypass in Advanced IP Blocker WordPress Plugin
slug: 2026-10-advanced-ip-blocker-auth-bypass
description: An authentication bypass vulnerability in the Advanced IP Blocker WordPress plugin enables unauthenticated attackers to brute-force MFA tokens and achieve complete site takeover via reusable nonces and lack of rate limiting.
date: "2026-10-10T05:33:42Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:wordpress:advanced_ip_blocker:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - wordpress
  - authentication-bypass
vendors:
  - WordPress
products:
  - Advanced IP Blocker (<= 8.13.13)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Unauthenticated attackers can leverage this to ... obtain an authenticated session cookie via wp_set_auth_cookie.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: This makes it possible for unauthenticated attackers to bypass authentication entirely ... by brute-forcing an unthrottled 6-digit TOTP code.
    confidence_band: high
cves:
  - id: CVE-2026-104732
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104732
rules:
  - title: Detect CVE-2026-104732 Exploitation Attempt
    description: Detects high-frequency POST requests to the Advanced IP Blocker plugin TOTP verification endpoint, indicating potential brute-force activity.
    platform: sigma
    severity: high
    tactics:
      - credential-access
    techniques:
      - T1110.001
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit WordPress installations for usage of Advanced IP Blocker plugin
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-104732
  mitigation_plan:
    - priority: immediate
      action: Disable 2FA feature in Advanced IP Blocker plugin until a patched version (version > 8.13.13) is available
      owner: IT Operations
      addresses: CVE-2026-104732
      evidence: Plugin vulnerable in versions up to 8.13.13
---

The Advanced IP Blocker plugin for WordPress is vulnerable to an authentication bypass in all versions up to and including 8.13.13. The vulnerability, tracked as CVE-2026-104732, exists because the `handle_login_action()` function fails to perform server-side validation that a user has successfully completed password authentication before processing step-two TOTP submissions. 

The plugin generates authentication nonces (`advaipbl-2fa-interim-{user_id}` and `advaipbl-2fa-verify-{user_id}`) based on a fixed, empty-session context, making them fully reusable by an attacker. Furthermore, the 2FA verification endpoint lacks rate limiting, account lockout mechanisms, and does not fire standard `wp_login_failed` hooks. An unauthenticated attacker knowing a valid user ID can leverage these flaws to brute-force a 6-digit TOTP code and obtain a valid authenticated session cookie via `wp_set_auth_cookie`. This flaw allows for full site takeover, including administrator accounts, without ever requiring the account password.

## Impact

Successful exploitation results in full unauthorized access to the WordPress environment as the targeted user. If an administrator account is targeted, the attacker gains complete control over the site, allowing for the execution of arbitrary code, data exfiltration, and persistence. Given the lack of rate limiting and logging on the 2FA verification process, attacks may remain undetected until the compromise is already complete.

## Recommendation

* Update the Advanced IP Blocker plugin to the latest version immediately once a patch is released to mitigate CVE-2026-104732.
* Disable the 2FA feature of the Advanced IP Blocker plugin if immediate updating is not possible, and rely on standard WordPress authentication or alternative, patched MFA providers.
* Review web server access logs for repeated POST requests to the plugin's login endpoint targeting specific user IDs.
* Monitor for unauthorized administrative sessions or modifications to user account privileges.
