---
title: LatePoint WordPress Plugin Stored XSS Vulnerability
slug: 2024-01-latepoint-xss
description: The LatePoint WordPress plugin is vulnerable to stored XSS via the booking_form_page_url parameter, allowing unauthenticated attackers to inject arbitrary web scripts in pages that execute when a user accesses the injected page.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - wordpress
  - xss
  - stored-xss
  - cve-2026-7332
  - plugin
vendors:
  - WordPress
products:
  - LatePoint – Calendar Booking Plugin for Appointments and Events plugin <= 5.5.0
cves:
  - id: CVE-2026-7332
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7332
rules:
  - title: Detect LatePoint XSS Attempt via booking_form_page_url
    description: Detects potential attempts to exploit the LatePoint stored XSS vulnerability by monitoring requests containing suspicious payloads in the booking_form_page_url parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
  - title: Detect LatePoint XSS in Activity Logs
    description: Detects stored XSS payloads in WordPress activity logs associated with the LatePoint plugin.
    platform: sigma
    severity: critical
    tactics:
      - persistence
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The LatePoint – Calendar Booking Plugin for Appointments and Events plugin for WordPress is susceptible to a stored cross-site scripting (XSS) vulnerability. This flaw, identified as CVE-2026-7332, exists in all versions up to and including 5.5.0. Unauthenticated attackers can exploit this vulnerability by injecting malicious web scripts into the 'booking_form_page_url' parameter. This vulnerability does not require Stripe to be configured. Successful exploitation allows attackers to execute arbitrary JavaScript code in the context of a user's browser when they access a page containing the injected script. This can lead to account compromise, data theft, or other malicious activities.

## Attack Chain

1. An unauthenticated attacker crafts a malicious URL containing a JavaScript payload in the `booking_form_page_url` parameter.
2. The attacker submits the crafted URL to a WordPress page utilizing the vulnerable LatePoint plugin.
3. The LatePoint plugin fails to properly sanitize or escape the input provided in the `booking_form_page_url` parameter.
4. The malicious script is stored in the WordPress database, specifically within the plugin's settings or booking data.
5. A legitimate user accesses the WordPress page where the malicious script is stored and rendered.
6. The user's browser executes the attacker-injected JavaScript code.
7. The malicious script can perform actions such as stealing cookies, redirecting the user to a phishing site, or modifying page content.
8. The attacker gains control over the user's session or injects further malicious content into the website.

## Impact

Successful exploitation of this stored XSS vulnerability allows an unauthenticated attacker to execute arbitrary JavaScript code in a user's browser. The potential impact includes session hijacking, defacement of the website, redirection to malicious sites, or the theft of sensitive information such as user credentials and financial data. While the specific number of affected installations is unknown, the LatePoint plugin is actively installed on WordPress sites, representing a significant attack surface.

## Recommendation

*   Upgrade the LatePoint – Calendar Booking Plugin for Appointments and Events to a version greater than 5.5.0 to patch CVE-2026-7332.
*   Deploy the Sigma rule `Detect LatePoint XSS Attempt via booking_form_page_url` to identify potential exploitation attempts by monitoring web server logs.
*   Review and sanitize existing data associated with the LatePoint plugin in the WordPress database for any injected malicious scripts.
