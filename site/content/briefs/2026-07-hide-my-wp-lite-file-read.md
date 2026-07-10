---
title: WordPress Hide My WP Lite Plugin Vulnerable to Arbitrary File Read (CVE-2026-13347)
slug: 2026-07-hide-my-wp-lite-file-read
description: The Hide My WP Lite plugin for WordPress, versions up to and including 1.3, is vulnerable to Arbitrary File Read (CVE-2026-13347) due to inadequate validation of user-supplied input in query parameters `he_wrapper_js` and `he_wrapper_css` within the `elementor_assets_filter()` function, allowing unauthenticated attackers to read arbitrary files on the server like `wp-config.php` when the Elementor plugin and 'Hide Elementor' feature are enabled.
date: "2026-07-10T08:18:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - plugin
  - arbitrary-file-read
  - path-traversal
  - web-application
  - cve
vendors:
  - WordPress
  - Elementor
products:
  - Hide My WP Lite <= 1.3
  - Elementor
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: This makes it possible for unauthenticated attackers to read the contents of arbitrary files on the affected site's server (such as wp-config).
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: This makes it possible for unauthenticated attackers to read the contents of arbitrary files on the affected site's server (such as wp-config).
    confidence_band: high
cves:
  - id: CVE-2026-13347
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13347
rules:
  - title: Detects CVE-2026-13347 Exploitation - Hide My WP Lite Arbitrary File Read
    description: Detects exploitation attempts against CVE-2026-13347 in the WordPress Hide My WP Lite plugin, involving path traversal sequences in `he_wrapper_js` or `he_wrapper_css` query parameters to trigger arbitrary file read.
    platform: sigma
    severity: high
    tactics:
      - collection
      - discovery
    techniques:
      - T1005
      - T1552
    data_sources:
      - webserver
rules_count: 1
---

The Hide My WP Lite plugin for WordPress, specifically versions up to and including 1.3, contains a critical arbitrary file read vulnerability tracked as CVE-2026-13347. This flaw stems from a path traversal vulnerability in the `elementor_assets_filter()` function, which fails to properly sanitize user-supplied input via the `he_wrapper_js` and `he_wrapper_css` query parameters. Attackers can leverage this by directly concatenating their input, containing path traversal sequences, with the `ABSPATH` variable, leading to `file_get_contents()` reading arbitrary files outside the intended directory. The content of these files is then echoed in the HTTP response, even though `wp_kses_post()` processes the output (this function only filters HTML tags and does not prevent file content disclosure). Successful exploitation, which does not require authentication, depends on the presence of the Elementor plugin and the activation of its 'Hide Elementor' feature. This vulnerability poses a significant risk as it allows unauthorized access to sensitive server files, such as `wp-config.php`, potentially leading to full compromise of the affected WordPress site.

## Attack Chain

1. An unauthenticated attacker crafts a malicious HTTP GET request targeting a WordPress site running the vulnerable Hide My WP Lite plugin (version 1.3 or earlier).
2. The request includes path traversal sequences (e.g., `../`) within the `he_wrapper_js` or `he_wrapper_css` query parameters.
3. The request targets a WordPress endpoint handled by the Hide My WP Lite plugin, specifically leveraging the `elementor_assets_filter()` function.
4. The `elementor_assets_filter()` function concatenates the attacker-supplied input, including the path traversal, with the absolute path to the WordPress installation (`ABSPATH`).
5. The resulting malicious path is then passed to the `file_get_contents()` PHP function.
6. `file_get_contents()` reads the content of an arbitrary file on the server, such as `/var/www/html/wp-config.php`.
7. The read file content is then echoed back in the HTTP response to the attacker.
8. The attacker successfully retrieves sensitive information from the server, like database credentials stored in `wp-config.php`.

## Impact

Successful exploitation of CVE-2026-13347 allows unauthenticated attackers to read any file accessible by the web server process. This includes highly sensitive files such as `wp-config.php`, which typically contains database connection credentials, authentication unique keys, and salts. Disclosure of `wp-config.php` content can lead to database compromise, complete administrative access to the WordPress site, and potentially further lateral movement within the server environment. This vulnerability affects WordPress sites utilizing the Hide My WP Lite plugin version 1.3 or earlier, provided the Elementor plugin is also installed and its 'Hide Elementor' feature is active. The CVSS v3.1 base score is 7.5 (High), reflecting the critical nature of information disclosure without authentication.

## Recommendation

* Deploy the Sigma rule provided in this brief to your web application firewall (WAF) or SIEM to detect attempts to exploit CVE-2026-13347.
* Ensure web server logs, specifically access logs, are configured to capture full HTTP request details, including method, URI, and query parameters, to enable detection of the specified indicators.
* Apply the latest patch or update to the Hide My WP Lite plugin to remediate CVE-2026-13347 as soon as possible.
* Implement strong file system permissions on your WordPress installation to minimize the impact if an arbitrary file read occurs, restricting read access to critical files to the absolute minimum necessary.
