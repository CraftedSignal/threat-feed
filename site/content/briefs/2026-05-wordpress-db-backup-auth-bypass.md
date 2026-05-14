---
title: CVE-2026-4031 - Database Backup for WordPress Plugin Authorization Bypass
slug: 2026-05-wordpress-db-backup-auth-bypass
description: CVE-2026-4031 is an authorization bypass vulnerability in the Database Backup for WordPress plugin (<= 2.5.2) that allows unauthenticated attackers to intercept database backup files by manipulating the backup directory via the wp_db_temp_dir parameter, leading to sensitive information exposure.
date: "2026-05-14T13:19:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - authorization-bypass
  - sensitive-data-exposure
  - cve
vendors:
  - WordPress
products:
  - Database Backup for WordPress plugin <= 2.5.2
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-4031
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4031
rules:
  - title: Detect Suspicious wp_db_temp_dir Parameter in wp-cron.php
    description: Detects suspicious POST requests to wp-cron.php with a potentially malicious wp_db_temp_dir parameter indicating a CVE-2026-4031 exploitation attempt.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
  - title: Detect Database Backup File Download from Public Directory
    description: Detects attempts to download database backup files from publicly accessible directories, potentially indicating successful CVE-2026-4031 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
rules_count: 2
---

The Database Backup for WordPress plugin, versions 2.5.2 and earlier, contains an authorization bypass vulnerability (CVE-2026-4031). This flaw stems from the plugin's failure to restrict access to the `wp_db_temp_dir` parameter. Unauthenticated attackers can exploit this vulnerability by sending a crafted request to `wp-cron.php`, poisoning the `wp_db_temp_dir` value to point to a publicly accessible directory, such as `wp-content/uploads/`. If a scheduled database backup is due, the attacker can intercept the backup file before it is cleaned up. The predictable naming convention of the backup file (based on database name, table prefix, date, and Swatch Internet Time) makes successful interception highly probable. This exploitation results in the exposure of sensitive information, including database credentials, user password hashes, and personally identifiable information (PII). This vulnerability requires that the site administrator has configured scheduled backups for exploitation.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site using the vulnerable Database Backup for WordPress plugin with scheduled backups enabled.
2. The attacker crafts a malicious HTTP request targeting `wp-cron.php`.
3. The request includes a poisoned `wp_db_temp_dir` parameter, setting it to a publicly accessible directory such as `wp-content/uploads/`.
4. The attacker sends the crafted HTTP request to the WordPress site's `wp-cron.php`.
5. If a scheduled database backup is triggered by the wp-cron.php execution, the plugin writes the backup file to the attacker-controlled directory.
6. The attacker leverages the predictable naming scheme (database name, table prefix, date, and Swatch Internet Time) to determine the exact filename of the backup.
7. The attacker retrieves the backup file from the publicly accessible directory via HTTP(S).
8. The attacker extracts sensitive information, including database credentials, user password hashes, and personally identifiable information, from the intercepted backup file.

## Impact

Successful exploitation of CVE-2026-4031 allows unauthenticated attackers to access sensitive information stored within the WordPress database backups. This includes database credentials, user password hashes, and personally identifiable information. The number of victims depends on the prevalence of the vulnerable plugin and the number of sites with scheduled backups enabled. This can lead to complete compromise of the WordPress site and potentially other systems if the database credentials are reused.

## Recommendation

*   Upgrade the Database Backup for WordPress plugin to the latest version (greater than 2.5.2) to patch CVE-2026-4031.
*   Monitor web server logs for POST requests to `wp-cron.php` with suspicious `wp_db_temp_dir` parameters (see Sigma rule `Detect Suspicious wp_db_temp_dir Parameter in wp-cron.php`).
*   Implement strict file access controls on the `wp-content/uploads/` directory to prevent unauthorized access to any files written there.
*   Review and restrict access to `wp-cron.php` to prevent unauthorized triggering of scheduled tasks.
