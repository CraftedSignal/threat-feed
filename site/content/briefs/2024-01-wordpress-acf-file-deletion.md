---
title: WordPress Advanced Members for ACF Plugin Arbitrary File Deletion Vulnerability
slug: 2024-01-wordpress-acf-file-deletion
description: The Advanced Members for ACF plugin for WordPress is vulnerable to arbitrary file deletion due to insufficient file path validation in the create_crop function, allowing authenticated attackers with Subscriber-level access or higher to delete arbitrary files, potentially leading to remote code execution.
date: "2024-01-17T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - wordpress
  - file-deletion
  - remote-code-execution
  - cve-2026-3243
vendors:
  - WordPress
products:
  - WordPress
  - Advanced Members for ACF plugin
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
cves:
  - id: CVE-2026-3243
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3243
rules:
  - title: Detect WordPress ACF Plugin Arbitrary File Deletion Attempt
    description: Detects potential exploitation attempts of the arbitrary file deletion vulnerability (CVE-2026-3243) in the Advanced Members for ACF plugin for WordPress.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
  - title: Detect wp-config.php Deletion via Web Server Logs
    description: Detects if wp-config.php file deletion occurs, which could be related to this exploit
    platform: sigma
    severity: critical
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Advanced Members for ACF plugin, a WordPress extension, contains an arbitrary file deletion vulnerability (CVE-2026-3243). This flaw resides within the `create_crop` function and stems from insufficient validation of file paths. All versions of the plugin up to and including 1.2.5 are affected. Exploitation requires an attacker to be authenticated with at least Subscriber-level privileges, a low barrier to entry on many WordPress sites. Successful exploitation enables the deletion of arbitrary files on the server, which can severely impact website functionality and, critically, can lead to remote code execution if sensitive files like `wp-config.php` are targeted. While version 1.2.5 includes a partial patch, complete remediation requires upgrading to a later version.

## Attack Chain

1.  Attacker gains Subscriber-level access to the WordPress instance, either through registration or compromised credentials.
2.  Attacker crafts a malicious HTTP request targeting the `create_crop` function within the Advanced Members for ACF plugin.
3.  The crafted request includes a manipulated file path designed to target a sensitive file on the server.
4.  Due to insufficient validation, the plugin processes the malicious file path without proper sanitization.
5.  The `create_crop` function attempts to perform a file deletion operation using the attacker-supplied path.
6.  The targeted file, such as `wp-config.php` or other critical system files, is successfully deleted from the server.
7.  The WordPress site becomes unstable or non-functional due to the missing configuration files.
8.  By deleting `wp-config.php` an attacker can trigger a WordPress reinstallation, potentially allowing them to gain administrative access and execute arbitrary code on the server, achieving Remote Code Execution.

## Impact

Successful exploitation of this vulnerability allows an attacker to delete arbitrary files on the WordPress server. This can lead to website defacement, data loss, and potentially remote code execution. Deletion of `wp-config.php`, a critical file containing database credentials, allows for complete takeover of the WordPress site. Given the widespread use of WordPress and the Advanced Members for ACF plugin, a successful attack could impact a large number of websites across various sectors. The CVSS v3.1 base score is 8.8, indicating a high severity vulnerability.

## Recommendation

*   Upgrade the Advanced Members for ACF plugin to the latest version to fully remediate CVE-2026-3243.
*   Monitor web server logs for suspicious POST requests to the `create_crop` function in the Advanced Members for ACF plugin, as highlighted in the Sigma rule below.
*   Implement file integrity monitoring (FIM) on critical WordPress files (e.g., `wp-config.php`, `.htaccess`) to detect unauthorized deletions.
*   Restrict Subscriber-level user permissions to minimize the attack surface, as this vulnerability requires authenticated access.
