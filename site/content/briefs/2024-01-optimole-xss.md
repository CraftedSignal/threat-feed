---
title: Optimole WordPress Plugin Stored XSS Vulnerability
slug: 2024-01-optimole-xss
description: The Optimole WordPress plugin before version 4.2.3 is vulnerable to stored cross-site scripting (XSS) due to insufficient input sanitization and output escaping on the 's' parameter (srcset descriptor) in the unauthenticated /wp-json/optimole/v1/optimizations REST endpoint, allowing unauthenticated attackers to inject arbitrary web scripts.
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - xss
  - plugin
  - cve-2026-5217
vendors:
  - Optimole
products:
  - Optimole WordPress Plugin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5217
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5217
rules:
  - title: Detect Suspicious Optimole REST API Requests
    description: Detects potentially malicious requests to the Optimole REST API endpoint used for injecting XSS payloads via the 's' parameter.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect WordPress Option Table Modification with Suspicious Content
    description: Detects suspicious modification of the WordPress options table, often used for storing malicious payloads.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Optimole – Optimize Images | Convert WebP & AVIF | CDN & Lazy Load | Image Optimization plugin, a WordPress plugin, contains a stored cross-site scripting (XSS) vulnerability affecting versions up to and including 4.2.2. This vulnerability stems from the plugin's inadequate handling of user-supplied input within the 's' parameter (srcset descriptor) of the `/wp-json/optimole/v1/optimizations` REST endpoint. An unauthenticated attacker can exploit this flaw by injecting malicious JavaScript code, which is then stored within the WordPress database and executed whenever a user accesses a page containing the injected code. The plugin's reliance on `sanitize_text_field()` only strips HTML tags and does not properly escape double quotes, and the exposure of HMAC signature and timestamp in the frontend allows unauthorized requests. This vulnerability can lead to account compromise, data theft, or other malicious activities.

## Attack Chain

1. An unauthenticated attacker crafts a malicious HTTP POST request to the `/wp-json/optimole/v1/optimizations` REST endpoint.
2. The attacker includes a payload containing a JavaScript injection within the 's' parameter (srcset descriptor). The payload leverages double quotes to inject arbitrary JavaScript.
3. The plugin validates the request using the exposed HMAC signature and timestamp values retrieved from the frontend HTML.
4. The plugin uses `sanitize_text_field()` on the descriptor value, which fails to escape the double quotes in the injected JavaScript code.
5. The poisoned descriptor is then stored as a WordPress transient, which is backed by the WordPress options table in the database.
6. When a user visits a page where the Optimole plugin is active, the plugin retrieves the stored descriptor from the database.
7. The plugin injects the malicious descriptor verbatim into the `srcset` attribute of an HTML tag via `tag_replacer.php` without proper escaping.
8. The victim's browser executes the injected JavaScript code, potentially leading to session hijacking, defacement, or redirection to malicious sites.

## Impact

Successful exploitation of this stored XSS vulnerability can lead to a range of severe consequences. An attacker could compromise administrator accounts, leading to full control of the WordPress site. Sensitive data, such as user credentials and customer information, could be stolen. The website could be defaced, leading to reputational damage. Furthermore, visitors to the website could be redirected to malicious sites, potentially infecting their devices with malware. The vulnerability affects all websites using the Optimole plugin version 4.2.2 or earlier.

## Recommendation

*   Upgrade the Optimole WordPress plugin to version 4.2.3 or later to patch CVE-2026-5217.
*   Inspect web server logs for POST requests to `/wp-json/optimole/v1/optimizations` containing suspicious characters or script-like syntax in the 's' parameter.
*   Deploy the Sigma rule to detect suspicious requests to the /wp-json/optimole/v1/optimizations endpoint.
