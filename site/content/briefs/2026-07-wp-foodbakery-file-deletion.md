---
title: WP Foodbakery Plugin Arbitrary File Deletion Vulnerability
slug: 2026-07-wp-foodbakery-file-deletion
description: The WP Foodbakery plugin for WordPress, specifically versions up to and including 4.9, is vulnerable to arbitrary file deletion (CVE-2026-15802) due to insufficient file path validation, allowing authenticated attackers with subscriber-level access to delete critical server files, potentially leading to remote code execution.
date: "2026-07-22T05:18:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - plugin
  - arbitrary-file-deletion
  - rce
  - cve
vendors:
  - Chimpstudio
products:
  - WP Foodbakery <= 4.9
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: delete arbitrary files on the server, which can easily lead to remote code execution when the right file is deleted (such as wp-config.php).
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: can easily lead to remote code execution when the right file is deleted (such as wp-config.php).
    confidence_band: high
cves:
  - id: CVE-2026-15802
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15802
  - https://themeforest.net/item/food-bakery-restaurant-bakery-responsive-wordpress-theme/18970331
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/45c8d883-1f97-4c9d-b406-c61e33a0959e?source=cve
rules:
  - title: Detects CVE-2026-15802 Exploitation - WP Foodbakery Arbitrary File Deletion
    description: Detects exploitation attempts against CVE-2026-15802, an arbitrary file deletion vulnerability in the WP Foodbakery WordPress plugin, by identifying web requests to the 'delete_locations_backup_file_callback' function with path traversal indicators.
    platform: sigma
    severity: high
    tactics:
      - execution
      - impact
    techniques:
      - T1059
      - T1485
    data_sources:
      - webserver
rules_count: 1
---

On July 22, 2026, the National Vulnerability Database (NVD) disclosed CVE-2026-15802, an arbitrary file deletion vulnerability affecting the WP Foodbakery plugin for WordPress, versions up to and including 4.9. This vulnerability stems from insufficient file path validation within the `delete_locations_backup_file_callback` function, allowing authenticated attackers with subscriber-level access or higher to delete arbitrary files on the server. The exploitation of this flaw can lead to severe consequences, including remote code execution (RCE) if critical files, such as `wp-config.php`, are deleted. This vulnerability presents a high risk to WordPress installations utilizing the affected plugin, as it could result in full site compromise, data loss, or disruption of service.

## Attack Chain

1. An attacker gains authenticated access to a WordPress site, requiring at least subscriber-level permissions.
2. The attacker identifies the presence and version of the vulnerable WP Foodbakery plugin (versions <= 4.9).
3. The attacker crafts a malicious HTTP request targeting the `delete_locations_backup_file_callback` function.
4. The request includes a path traversal sequence (e.g., `../`, `..%2f`) within the file path parameter.
5. Due to insufficient file path validation, the plugin processes the manipulated path.
6. The plugin's vulnerable function deletes an arbitrary file on the server specified by the attacker's crafted path.
7. By deleting a critical file like `wp-config.php`, the attacker forces a WordPress reinstallation or gains RCE through subsequent site misconfiguration.

## Impact

Successful exploitation of CVE-2026-15802 allows authenticated attackers to delete arbitrary files on the affected WordPress server. This can lead to denial of service due to critical file removal or, more severely, remote code execution. If the `wp-config.php` file is deleted, it can force a WordPress reinstallation, potentially enabling an attacker to reconfigure the site with malicious settings or gain full control. The direct impact includes data loss, website defacement, and unauthorized access to the underlying server environment, affecting the confidentiality, integrity, and availability of the web application and its data.

## Recommendation

* Patch CVE-2026-15802 immediately by updating the WP Foodbakery plugin to a version greater than 4.9 to address the arbitrary file deletion vulnerability.
* Deploy the provided Sigma rule to your SIEM solution to detect suspicious web server requests indicative of CVE-2026-15802 exploitation attempts.
* Configure your Web Application Firewall (WAF) to block HTTP requests containing path traversal sequences (e.g., `../`, `..%2f`, `%2e%2e%2f`) targeting known WordPress AJAX endpoints or file deletion functions, particularly those related to the `delete_locations_backup_file_callback` function.
* Review web server access logs for any suspicious activity related to `/wp-admin/admin-ajax.php` and the `delete_locations_backup_file_callback` action parameter.
