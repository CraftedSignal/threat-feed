---
title: Database Backup for WordPress Plugin Arbitrary File Read and Deletion Vulnerability (CVE-2026-4030)
slug: 2026-05-wordpress-db-backup-file-read-deletion
description: The Database Backup for WordPress plugin before 2.5.3 is vulnerable to unauthenticated arbitrary file read and deletion due to improper authorization checks and user-controlled backup directories, leading to sensitive information exposure and potential site takeover on WordPress Multisite environments.
date: "2026-05-14T13:19:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - file_read
  - file_deletion
  - cve
vendors:
  - WordPress
products:
  - Database Backup for WordPress plugin <= 2.5.2
cves:
  - id: CVE-2026-4030
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4030
  - CVE-2026-4030
rules:
  - title: Detects CVE-2026-4030 Exploitation — Arbitrary File Read Attempt via Database Backup Plugin
    description: Detects CVE-2026-4030 exploitation — Monitors web server logs for HTTP requests targeting the Database Backup for WordPress plugin with suspicious file paths, indicating a possible arbitrary file read attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-4030 Exploitation — Arbitrary File Deletion Attempt via Database Backup Plugin
    description: Detects CVE-2026-4030 exploitation — Monitors web server logs for HTTP requests attempting to delete files outside the designated backup directory using the Database Backup for WordPress plugin.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

The Database Backup for WordPress plugin, versions 2.5.2 and earlier, contains an arbitrary file read and deletion vulnerability (CVE-2026-4030). This flaw stems from the plugin's failure to properly enforce the return value of its authorization checks. Coupled with a user-controlled backup directory parameter, this weakness allows unauthenticated attackers to read and delete arbitrary files on the affected WordPress server. This vulnerability is only exploitable in WordPress Multisite environments where the deprecated `is_site_admin()` function exists. Successful exploitation can lead to sensitive information exposure and potential site takeover, impacting the confidentiality and integrity of the targeted WordPress installation.

## Attack Chain

1.  An unauthenticated attacker identifies a WordPress Multisite installation using the vulnerable Database Backup for WordPress plugin (<= 2.5.2).
2.  The attacker crafts a malicious HTTP request targeting the plugin's functionality related to backup directory handling.
3.  The crafted request leverages the user-controlled backup directory parameter to specify a target file path outside the intended backup directory.
4.  The plugin fails to properly validate or sanitize the provided file path due to the insufficient authorization check.
5.  The plugin attempts to access the specified file based on the attacker-controlled path.
6.  If the request is for file reading, the plugin exposes the contents of the targeted file to the attacker in the HTTP response. If the request is for file deletion, the targeted file is removed from the server.
7.  The attacker gains unauthorized access to sensitive information, such as configuration files, database credentials, or other user data.
8.  The attacker uses the exposed information to further compromise the WordPress installation, potentially leading to a full site takeover.

## Impact

Successful exploitation of CVE-2026-4030 allows unauthenticated attackers to read arbitrary files on the server. This can lead to the exposure of sensitive information, including configuration files, database credentials, and user data. Attackers can also delete arbitrary files, potentially disrupting website functionality and leading to data loss. In WordPress Multisite environments, this can lead to a full site takeover, affecting all sites within the network. The overall impact is a compromise of confidentiality, integrity, and availability of the affected WordPress installation.

## Recommendation

*   Upgrade the Database Backup for WordPress plugin to version 2.5.3 or later to patch CVE-2026-4030.
*   Monitor web server logs for suspicious requests containing file paths outside the intended backup directory to detect potential exploitation attempts. Deploy the Sigma rules provided in this brief to your SIEM.
*   Implement strong file permission controls on the WordPress server to limit access to sensitive files.
*   Consider disabling the Database Backup for WordPress plugin in WordPress Multisite environments if the `is_site_admin()` function is deprecated.
*   Review WordPress Multisite configurations and ensure proper access controls are in place to prevent unauthorized file access.
*   Enable webserver logging to capture cs-uri-stem and cs-uri-query for request analysis (see Sigma rule).
