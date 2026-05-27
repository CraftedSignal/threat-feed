---
title: HBook WordPress Plugin Stored XSS Vulnerability (CVE-2026-8143)
slug: 2026-05-hbook-xss
description: The HBook plugin for WordPress is vulnerable to Stored Cross-Site Scripting (XSS) via the 'hb_country_iso', 'hb_usa_state_iso', and 'hb_canada_province_iso' parameters (CVE-2026-8143) in versions up to 2.1.6, potentially leading to arbitrary script execution in the administrator's browser.
date: "2026-05-27T08:20:53Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - wordpress
  - xss
  - plugin
vendors:
  - Wordfence
products:
  - HBook plugin (<= 2.1.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-8143
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8143
  - https://codecanyon.net/item/hbook-hotel-booking-system-wordpress-plugin/15059946
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/e1c16bcb-c188-4e01-9d0b-e4e1a1ef82ee?source=cve
rules:
  - title: Detect HBook WordPress Plugin Stored XSS Attempt
    description: Detects CVE-2026-8143 exploitation — attempts to inject XSS payloads into HBook plugin parameters.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
  - title: Detect HBook WordPress Plugin XSS via POST Request
    description: Detects CVE-2026-8143 exploitation — HTTP POST requests containing XSS payloads targeting the 'hb_country_iso', 'hb_usa_state_iso', or 'hb_canada_province_iso' parameters of the HBook plugin.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
rules_count: 2
---

The HBook plugin for WordPress is susceptible to a stored Cross-Site Scripting (XSS) vulnerability affecting versions 2.1.6 and earlier. The vulnerability, identified as CVE-2026-8143, stems from insufficient input sanitization and output escaping of the 'hb_country_iso', 'hb_usa_state_iso', and 'hb_canada_province_iso' parameters. An unauthenticated attacker can inject malicious JavaScript code into these parameters, which is then stored in the WordPress database. When an administrator accesses the affected page (the HBook Customers admin page), the stored XSS payload is executed within their browser, potentially leading to account takeover or further malicious actions.

## Attack Chain

1.  An unauthenticated attacker crafts a malicious HTTP request targeting the HBook plugin.
2.  The attacker injects a JavaScript payload into the 'hb_country_iso', 'hb_usa_state_iso', or 'hb_canada_province_iso' parameters.
3.  The vulnerable HBook plugin fails to properly sanitize or escape the injected payload.
4.  The malicious payload is stored in the WordPress database.
5.  An administrator logs into the WordPress administration panel and navigates to the HBook Customers admin page.
6.  The HBook plugin retrieves the stored data from the database, including the malicious payload.
7.  The plugin renders the page, executing the injected JavaScript code in the administrator's browser.
8.  The attacker can then potentially steal session cookies, perform actions on behalf of the administrator, or redirect the administrator to a malicious website.

## Impact

Successful exploitation of this stored XSS vulnerability (CVE-2026-8143) can lead to account compromise, where an attacker gains control of an administrator's WordPress account. This access could then be leveraged to further compromise the WordPress website, install malicious plugins, modify content, or deface the site. The severity is amplified by the fact that no authentication is required to inject the malicious payload.

## Recommendation

*   Upgrade the HBook WordPress plugin to the latest version, which includes a fix for CVE-2026-8143.
*   Deploy the Sigma rule "Detect HBook WordPress Plugin Stored XSS Attempt" to identify potential exploitation attempts in web server logs.
*   Implement input validation and output encoding/escaping for all user-supplied data within WordPress plugins to prevent future XSS vulnerabilities.
