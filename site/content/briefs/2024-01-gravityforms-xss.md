---
title: Gravity Forms Plugin Unauthenticated Stored XSS Vulnerability
slug: 2024-01-gravityforms-xss
description: The Gravity Forms plugin for WordPress is vulnerable to Unauthenticated Stored Cross-Site Scripting (XSS) in versions up to and including 2.10.0, allowing unauthenticated attackers to inject arbitrary web scripts via form submissions that execute when an administrator views the entry detail page.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - xss
  - wordpress
  - gravityforms
vendors:
  - WordPress
products:
  - Gravity Forms plugin
cves:
  - id: CVE-2026-5112
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5112
rules:
  - title: Detect Gravity Forms XSS via Product Name
    description: Detects potential XSS attempts in Gravity Forms Calculation Product field names by looking for common HTML tags or script-related keywords in form submission data.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
  - title: Detect Gravity Forms Admin Entry Access with Suspicious Product Name
    description: Detects access to Gravity Forms entry detail pages in the WordPress admin panel where the entry data contains potentially malicious script-related keywords, indicating possible XSS exploitation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Gravity Forms plugin for WordPress, a widely used form management tool, contains a vulnerability that can be exploited by unauthenticated attackers. Specifically, versions up to and including 2.10.0 are susceptible to Stored Cross-Site Scripting (XSS) due to insufficient input validation and output escaping of Calculation Product field names within Repeater fields. This flaw resides in how the plugin processes and renders form submissions containing malicious HTML within the product name field. The vulnerability allows an attacker to inject arbitrary web scripts that execute in the context of an authenticated administrator's session when they access the entry detail page within the WordPress admin panel. Successful exploitation enables attackers to perform actions with the privileges of the compromised administrator.

## Attack Chain

1.  An unauthenticated attacker crafts a malicious form submission.
2.  The malicious payload is placed in the Calculation Product field's product name (.1) within a Repeater field.
3.  The `validate()` method in the `GF_Field_Calculation` class inadequately validates the product name field, failing to sanitize malicious HTML.
4.  The `sanitize_entry_value()` method returns the raw, unsanitized value for the product name field, as HTML sanitization is not expected for this field.
5.  The malicious form submission is saved as an entry in WordPress.
6.  An authenticated administrator with the `gravityforms_view_entries` capability accesses the entry detail page in `wp-admin`.
7.  The `get_value_entry_detail()` method concatenates the unsanitized product name directly into the output string.
8.  The repeater's `get_value_entry_detail()` method renders the unsanitized output, leading to the execution of the injected XSS payload within the administrator's browser.

## Impact

Successful exploitation allows an unauthenticated attacker to execute arbitrary JavaScript code within the context of an authenticated WordPress administrator's session. This can lead to account takeover, data theft, or further malicious actions performed on the WordPress site. While the number of potentially affected sites is large due to the plugin's popularity, the impact is limited to administrators who access the specific entry containing the malicious payload.

## Recommendation

*   Upgrade the Gravity Forms plugin to a version greater than 2.10.0 to patch CVE-2026-5112.
*   Implement the Sigma rule `Detect Gravity Forms XSS via Product Name` to detect attempts to inject malicious scripts into product names.
*   Review and audit existing Gravity Forms entries for suspicious content in Calculation Product fields to identify potential exploitation attempts.
