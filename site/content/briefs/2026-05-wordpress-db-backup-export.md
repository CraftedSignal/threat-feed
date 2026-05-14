---
title: 'CVE-2026-4029: Database Backup for WordPress Plugin Unauthorized Database Export'
slug: 2026-05-wordpress-db-backup-export
description: The Database Backup for WordPress plugin up to version 2.5.2 is vulnerable to unauthorized database export due to improper authorization enforcement, allowing unauthenticated attackers to export database tables in WordPress Multisite environments.
date: "2026-05-14T13:19:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - wordpress
  - database backup
  - unauthenticated access
  - data exfiltration
vendors:
  - WordPress
products:
  - Database Backup for WordPress plugin <= 2.5.2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-4029
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4029
rules:
  - title: Detect Unauthorized WordPress Database Export
    description: Detects CVE-2026-4029 exploitation — unauthorized access to database export functionality in WordPress Database Backup plugin.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Access to WordPress Plugin Directory
    description: Detects suspicious access to the WordPress plugin directory, which may indicate reconnaissance activity.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595.001
    data_sources:
      - webserver
rules_count: 2
---

The Database Backup for WordPress plugin, in versions up to and including 2.5.2, is vulnerable to an unauthorized database export flaw. This vulnerability, identified as CVE-2026-4029, stems from the plugin's failure to properly enforce the return value of its authorization check. The vulnerability specifically affects WordPress Multisite environments where the deprecated `is_site_admin()` function is present. Successful exploitation allows unauthenticated attackers to export database tables, potentially leading to sensitive information exposure. Defenders should ensure the plugin is updated to a version beyond 2.5.2 or implement compensating controls to restrict access to database export functionality.

## Attack Chain

1.  Attacker identifies a WordPress Multisite instance using Database Backup for WordPress plugin version 2.5.2 or earlier.
2.  Attacker crafts a malicious HTTP request to the plugin's database export functionality, bypassing the intended authorization checks.
3.  The plugin's authorization check fails to properly validate the user's permissions due to improper enforcement of the return value.
4.  The plugin initiates a database export operation.
5.  The database tables are exported and made accessible to the unauthenticated attacker.
6.  The attacker downloads the exported database, which contains sensitive information.
7.  Attacker analyzes the database content to extract sensitive credentials, configuration details, or user data.

## Impact

Successful exploitation of CVE-2026-4029 allows unauthenticated attackers to export sensitive database tables from vulnerable WordPress Multisite installations. This can lead to the exposure of usernames, passwords, API keys, customer data, and other confidential information stored in the database. The impact is high due to the potential for complete compromise of the affected WordPress site and the sensitive data it manages.

## Recommendation

*   Upgrade the Database Backup for WordPress plugin to the latest version (greater than 2.5.2) to patch CVE-2026-4029.
*   Monitor web server logs for suspicious requests to database export endpoints associated with the Database Backup for WordPress plugin, using the Sigma rule `Detect Unauthorized WordPress Database Export`.
*   In WordPress Multisite environments, investigate any unusual activity related to the `is_site_admin()` function or database backup operations.
