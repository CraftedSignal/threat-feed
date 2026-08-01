---
title: Authentication Bypass in Single Sign On For TNG WordPress Plugin
slug: 2026-08-tng-auth-bypass
description: An unauthenticated password reset vulnerability in the Single Sign On For TNG plugin (CVE-2026-15964) allows attackers to perform full site takeover by bypassing AJAX nonce protections.
date: "2026-08-01T09:49:47Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - WordPress
products:
  - Single Sign On For TNG (<= 2.0.0)
cves:
  - id: CVE-2026-15964
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15964
rules:
  - title: Detect CVE-2026-15964 Exploitation Attempts
    description: Detects unauthorized password reset requests targeting the ssoprocess_ajax action in the Single Sign On For TNG plugin.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1550.001
      - T1556.002
    data_sources:
      - webserver
rules_count: 1
---

The Single Sign On For TNG plugin for WordPress, in versions up to and including 2.0.0, contains a critical authentication bypass vulnerability (CVE-2026-15964). The flaw resides in the `ssoprocess_ajax()` function, which is exposed to unauthenticated users via the `wp_ajax_nopriv_ssoprocess_ajax` action. By submitting a `setnewpassword` operation along with a target user's email address, an attacker can trigger the `reset_password()` function without any ownership verification, such as an email confirmation or security token. 

Although the function attempts to implement a CSRF guard using `check_ajax_referer()`, the required `ssoajaxnonce` is exposed globally to all visitors via the `SSOPWDREQUIREMENT` JavaScript object injected into front-end pages. Because WordPress generates nonces for unauthenticated sessions, an attacker can scrape this value from the site's homepage and successfully authorize their malicious password reset request. This vulnerability enables unauthenticated attackers to hijack any user account, including administrative accounts, resulting in complete site takeover.

## Attack Chain

1. Attacker navigates to the public-facing homepage of the target WordPress site.
2. Attacker inspects the HTML source or JavaScript objects to retrieve the `SSOPWDREQUIREMENT` object containing the `ssoajaxnonce`.
3. Attacker crafts an HTTP POST request to the WordPress `admin-ajax.php` endpoint.
4. Attacker includes the `action` parameter set to `ssoprocess_ajax` and the `operation` parameter set to `setnewpassword`.
5. Attacker provides the `email` parameter corresponding to the target administrative or privileged account.
6. Attacker includes the scraped `ssoajaxnonce` in the request headers or body to satisfy `check_ajax_referer()`.
7. The plugin executes `reset_password()` for the specified email account, overwriting the legitimate password.
8. Attacker logs into the target account with the new password to achieve full site takeover.

## Impact

Successful exploitation of CVE-2026-15964 allows an unauthenticated attacker to reset the password of any user registered on the WordPress instance. If a site administrator's email is known, the attacker can gain full administrative control, leading to potential data exfiltration, injection of malicious payloads into the site, or complete site defacement. This vulnerability affects all installations of the plugin version 2.0.0 and earlier.

## Recommendation

1. Immediately update the "Single Sign On For TNG" plugin to the latest patched version available.
2. Monitor web server logs for suspicious POST requests to `admin-ajax.php` where the `action` parameter is `ssoprocess_ajax`.
3. Audit WordPress user accounts for unexpected password resets or unauthorized account activity.
4. Disable the plugin functionality if an immediate update is not feasible.
