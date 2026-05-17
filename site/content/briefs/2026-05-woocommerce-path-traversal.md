---
title: WooCommerce CSV Importer Path Traversal File Deletion (CVE-2018-25325)
slug: 2026-05-woocommerce-path-traversal
description: WooCommerce CSV Importer 3.3.6 contains a path traversal vulnerability (CVE-2018-25325) that allows registered users to delete arbitrary files by submitting crafted filenames via the delete_export_file AJAX action.
date: "2026-05-17T13:18:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - file-deletion
  - wordpress
vendors:
  - Woocommerce
products:
  - CSV Importer 3.3.6
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2018-25325
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25325
  - http://lenonleite.com.br/
  - https://www.exploit-db.com/exploits/44433
  - https://www.vulncheck.com/advisories/woocommerce-csv-importer-path-traversal-file-deletion
rules:
  - title: Detect CVE-2018-25325 Exploitation — WooCommerce CSV Importer Path Traversal
    description: Detects CVE-2018-25325 exploitation — HTTP POST requests to wp-admin/admin-ajax.php with path traversal sequences in the filename parameter for delete_export_file action.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Suspicious File Deletion via PHP
    description: Detects attempts to delete files via PHP scripts, which could be indicative of path traversal exploitation.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

WooCommerce CSV Importer version 3.3.6 is vulnerable to a path traversal vulnerability (CVE-2018-25325). This flaw allows any registered user, even those with low privileges, to delete arbitrary files on the server. The vulnerability is triggered via the `delete_export_file` AJAX action, where the `filename` parameter is not properly sanitized. By crafting a POST request with directory traversal sequences (e.g., `../`), an attacker can bypass intended directory restrictions and delete sensitive files such as `wp-config.php`. This vulnerability poses a significant risk to WordPress installations using the affected plugin.

## Attack Chain

1. An attacker registers an account on the WordPress site if one does not exist.
2. The attacker identifies the `delete_export_file` AJAX action as a target for manipulation.
3. The attacker crafts a POST request to `wp-admin/admin-ajax.php` with the action set to `delete_export_file`.
4. The POST request includes a `filename` parameter containing a path traversal sequence, such as `../../../../wp-config.php`.
5. The server-side code, lacking proper input validation, processes the request and attempts to delete the file specified by the crafted filename.
6. Due to the path traversal, the server deletes a file outside of the intended export directory.
7. If the attacker successfully targets critical files like `wp-config.php`, the WordPress site may become unstable or inaccessible.

## Impact

Successful exploitation of this vulnerability can lead to arbitrary file deletion on the server hosting the WordPress site. An attacker could delete critical configuration files like `wp-config.php`, rendering the website unusable. The CVSS v3.1 base score for this vulnerability is 7.5, indicating a high severity. While the provided source doesn't list specific victim counts or sectors, the widespread use of WooCommerce makes this vulnerability a significant threat.

## Recommendation

*   Upgrade to a patched version of the WooCommerce CSV Importer that addresses the path traversal vulnerability (CVE-2018-25325).
*   Implement the provided Sigma rule "Detect CVE-2018-25325 Exploitation — WooCommerce CSV Importer Path Traversal" to detect malicious POST requests attempting to exploit this vulnerability.
*   Monitor web server logs for POST requests to `wp-admin/admin-ajax.php` with the `delete_export_file` action and filenames containing directory traversal sequences (`../`) to identify potential exploitation attempts.
