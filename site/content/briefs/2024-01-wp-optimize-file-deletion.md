---
title: WP-Optimize Plugin Vulnerable to Arbitrary File Deletion
slug: 2024-01-wp-optimize-file-deletion
description: The WP-Optimize plugin for WordPress is vulnerable to arbitrary file deletion due to insufficient file path validation, allowing authenticated attackers with author-level access or higher to delete arbitrary files, potentially leading to remote code execution.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - file-deletion
  - rce
vendors:
  - WordPress
products:
  - WP-Optimize – Cache, Compress images, Minify & Clean database to boost page speed & performance <= 4.5.2
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1202
    technique_name: Indirect Command Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1202
    technique_name: Indirect Command Execution
cves:
  - id: CVE-2026-7252
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7252
rules:
  - title: WP-Optimize Arbitrary File Deletion Attempt
    description: Detects attempts to modify the 'original-file' meta key in WordPress to point to sensitive files, potentially leading to arbitrary file deletion via the WP-Optimize plugin.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1202
    data_sources:
      - webserver
      - linux
  - title: WP-Optimize Arbitrary File Deletion RCE via wp-config.php
    description: Detects web requests resulting in a 200 or 404 response, targeting wp-config.php, indicating potential deletion via WP-Optimize leading to RCE.
    platform: sigma
    severity: critical
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1202
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The WP-Optimize – Cache, Compress images, Minify & Clean database to boost page speed & performance plugin, a widely used WordPress plugin, contains a critical vulnerability that allows authenticated attackers with author-level permissions and above to delete arbitrary files on the server. This vulnerability, identified as CVE-2026-7252, stems from insufficient file path validation in the `unscheduled_original_file_deletion` function within the plugin. The issue affects all versions up to and including 4.5.2. Successful exploitation can lead to complete compromise of the WordPress installation, including remote code execution by deleting critical files such as `wp-config.php`. The attack is facilitated by the fact that `original-file` is a publicly accessible meta key.

## Attack Chain

1. An attacker obtains author-level or higher access to a WordPress site with the vulnerable WP-Optimize plugin installed.
2. The attacker identifies the `original-file` meta key associated with an attachment post.
3. The attacker modifies the `original-file` meta key via the Edit Media form or the REST API to point to a sensitive file on the server, such as `wp-config.php`.
4. The `unscheduled_original_file_deletion` function is triggered (likely via a scheduled task or other plugin functionality that utilizes the meta key).
5. Due to the insufficient file path validation, the plugin attempts to delete the file specified in the modified `original-file` meta key (e.g., `wp-config.php`).
6. The sensitive file is successfully deleted from the server.
7. The attacker leverages the deleted sensitive file to achieve remote code execution, potentially by exploiting missing configuration or using alternative attack vectors.

## Impact

Successful exploitation of this vulnerability allows attackers to delete arbitrary files on the WordPress server. This can lead to a complete loss of website functionality, data corruption, and potential remote code execution. Deleting configuration files, such as `wp-config.php`, can allow attackers to gain control of the database and the entire WordPress installation. Given the popularity of the WP-Optimize plugin, a large number of WordPress websites are potentially vulnerable.

## Recommendation

*   Upgrade the WP-Optimize plugin to a version greater than 4.5.2 to patch CVE-2026-7252.
*   Deploy the Sigma rule "WP-Optimize Arbitrary File Deletion Attempt" to detect attempts to modify the `original-file` meta key to point to sensitive files.
*   Monitor WordPress access logs for suspicious activity related to the Edit Media form and REST API endpoints to detect unauthorized modifications of attachment metadata.
