---
title: WordPress Backup Migration Plugin Unauthenticated Database Backup Download
slug: 2026-05-wordpress-backup-migration-info-disclosure
description: WordPress Plugin Backup Migration 1.2.8 contains an information disclosure vulnerability allowing unauthenticated attackers to download complete database backups by accessing predictable file paths.
date: "2026-05-05T12:16:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - information-disclosure
  - wordpress
  - cve-2023-54346
vendors:
  - WordPress
products:
  - Backup Migration plugin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2023-54346
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2023-54346
  - https://www.vulncheck.com/advisories/wordpress-plugin-backup-migration-unauthenticated-database-backup-download
  - https://www.exploit-db.com/exploits/51445
rules:
  - title: Detect WordPress Backup Directory Enumeration
    description: Detects attempts to enumerate WordPress backup directories by monitoring web server logs for suspicious file requests.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1595.002
    data_sources:
      - webserver
      - linux
  - title: Detect WordPress Backup File Download
    description: Detects direct downloads of WordPress backup files by monitoring web server logs for requests to common backup file extensions within the WordPress content directory.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

WordPress Plugin Backup Migration 1.2.8 is vulnerable to information disclosure. Unauthenticated attackers can exploit this flaw to download complete database backups by accessing predictable file paths. The vulnerability, identified as CVE-2023-54346, allows attackers to enumerate backup directories through configuration files and logs. This enumeration enables the construction of direct download URLs, which, when accessed, retrieve sensitive backup archives containing full database dumps. This poses a significant risk to WordPress sites using the affected plugin version, as it allows unauthorized access to sensitive data.

## Attack Chain

1.  Attacker identifies a WordPress site using the Backup Migration plugin version 1.2.8.
2.  Attacker accesses publicly available configuration files (e.g., wp-config.php) to gather information about the site's structure.
3.  The attacker attempts to access log files created by the Backup Migration plugin to identify backup directory names.
4.  Attacker identifies predictable file paths for backup files based on the enumerated backup directory names.
5.  The attacker constructs direct download URLs for backup archive files (e.g., .zip or .sql) based on the identified paths.
6.  The attacker sends an HTTP GET request to the constructed URL.
7.  The server responds with the backup archive file containing the complete WordPress database.
8.  Attacker downloads and extracts the database backup, gaining access to sensitive information, including user credentials, site configuration, and potentially other data.

## Impact

Successful exploitation of this vulnerability allows attackers to download complete WordPress database backups, potentially exposing sensitive information such as user credentials, configuration details, and proprietary data. The impact is significant, as it could lead to account compromise, data theft, and further malicious activities. This vulnerability affects all WordPress sites using the Backup Migration plugin version 1.2.8 that have not applied a patch.

## Recommendation

*   Deploy the Sigma rule `Detect WordPress Backup Directory Enumeration` to identify potential attempts to discover backup directories by monitoring web server logs for suspicious file requests.
*   Deploy the Sigma rule `Detect WordPress Backup File Download` to detect direct downloads of backup files by monitoring web server logs for requests to common backup file extensions within the WordPress content directory.
*   Upgrade the Backup Migration plugin to a version that addresses CVE-2023-54346.
