---
title: WordPress Easy PayPal Events & Tickets Plugin Authentication Bypass Vulnerability
slug: 2026-05-wordpress-paypal-auth-bypass
description: An unauthenticated remote attacker can exploit a hardcoded authentication bypass vulnerability in the Easy PayPal Events & Tickets plugin for WordPress (versions 1.3 and earlier) by providing 'test' as the hash parameter, allowing retrieval of sensitive order details.
date: "2026-05-04T18:16:27Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - authentication bypass
  - vulnerability
vendors:
  - WordPress
products:
  - Easy PayPal Events & Tickets plugin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-32834
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32834
iocs:
  - type: email
    value: customer email addresses
ioc_counts:
  email: 1
rules:
  - title: Detect WordPress Easy PayPal Events & Tickets Authentication Bypass Attempt
    description: Detects attempts to exploit the hardcoded authentication bypass vulnerability (CVE-2026-32834) in the Easy PayPal Events & Tickets plugin for WordPress by monitoring requests with the 'test' hash.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect WordPress AJAX endpoint abuse
    description: Detects requests to the WordPress AJAX endpoint with unusual parameters that could indicate exploit attempts
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Easy PayPal Events & Tickets plugin for WordPress, version 1.3 and earlier, contains a critical hardcoded authentication bypass vulnerability (CVE-2026-32834) within its QR code scanning functionality. This flaw allows unauthenticated remote attackers to bypass hash verification by supplying the string 'test' as the hash parameter when accessing the `add_wpeevent_button_qr` action. This bypass enables attackers to retrieve sensitive order details associated with any post ID, including PayPal transaction IDs, customer email addresses, purchase amounts, and ticket information. The vulnerable plugin was officially closed on March 18, 2026, making it imperative to identify and mitigate any remaining installations to prevent potential data breaches.

## Attack Chain

1.  Attacker identifies a WordPress site using the Easy PayPal Events & Tickets plugin (version 1.3 or earlier).
2.  Attacker crafts a malicious HTTP GET request targeting the `/wp-admin/admin-ajax.php` endpoint.
3.  The request includes the `action` parameter set to `add_wpeevent_button_qr`.
4.  The request includes a `hash` parameter set to the hardcoded value `test`.
5.  The request includes a `post_id` parameter, either guessed or obtained through other means.
6.  The vulnerable plugin bypasses authentication due to the hardcoded hash.
7.  The plugin processes the request and retrieves sensitive order details associated with the provided `post_id`.
8.  The attacker receives the sensitive data, including PayPal transaction IDs, customer email addresses, purchase amounts, and ticket information.

## Impact

Successful exploitation of this vulnerability grants unauthenticated attackers access to sensitive customer and transaction data associated with events and tickets managed through the Easy PayPal Events & Tickets plugin. The leaked information, including customer email addresses and PayPal transaction IDs, can be used for further malicious activities such as phishing campaigns, identity theft, and financial fraud. The number of affected WordPress sites is unknown, but any site using a vulnerable version of the plugin is at risk.

## Recommendation

*   Deploy the Sigma rule `Detect WordPress Easy PayPal Events & Tickets Authentication Bypass Attempt` to your SIEM to detect exploitation attempts targeting the vulnerable endpoint.
*   Inspect web server logs for requests to `/wp-admin/admin-ajax.php` with the `action` parameter set to `add_wpeevent_button_qr` and the `hash` parameter set to `test` to identify potential exploitation attempts.
*   Monitor network traffic for suspicious data exfiltration following the identified exploitation attempts to mitigate potential damage.
*   If the plugin is still installed, remove it immediately.
