---
title: Information Exposure in Keep Backup Daily WordPress Plugin
slug: 2026-08-keep-backup-daily-exposure
description: The Keep Backup Daily plugin for WordPress before 2.1.4 contains a vulnerability allowing unauthenticated attackers to trigger database backups and retrieve them via predictable filenames.
date: "2026-08-31T17:58:26Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:keep_backup_daily:keep_backup_daily:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - vulnerability
  - web-application
  - data-exfiltration
vendors:
  - WordPress
products:
  - Keep Backup Daily (< 2.1.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can trigger a full MySQL database dump by accessing the 'kbd_cron_process' parameter.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: Attackers can download the generated backup from the publicly accessible uploads directory.
    confidence_band: high
cves:
  - id: CVE-2026-75133
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75133
rules:
  - title: Detect CVE-2026-75133 Exploitation - Unauthenticated Backup Trigger
    description: Detects unauthenticated attempts to invoke the kbd_cron_process parameter which initiates database backups.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Keep Backup Daily to 2.1.4
      owner: IT Operations
      due: 24h
      evidence: Source defines 2.1.4 as the fixed version.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Keep Backup Daily to 2.1.4
      owner: IT Operations
      addresses: CVE-2026-75133
      evidence: NVD advisory
---

The Keep Backup Daily plugin for WordPress (versions prior to 2.1.4) is vulnerable to a sensitive information exposure flaw. This vulnerability allows an unauthenticated attacker to initiate a full MySQL database dump by invoking the `kbd_cron_process` parameter. The plugin generates backup files in the site's publicly accessible `uploads` directory. Because the naming convention for these backup files is partially predictable - based on the database name, a limited randomization factor, and the current Unix timestamp - attackers can enumerate and download these sensitive backups. This exposes the entire site database, including user credentials, configuration secrets, and other sensitive content. This vulnerability is critical for environments where the plugin is enabled, as it provides an automated pathway for total data exfiltration without requiring privileged access.

## Attack Chain

1. Attacker performs reconnaissance to identify WordPress sites running the Keep Backup Daily plugin.
2. Attacker sends an unauthenticated HTTP GET/POST request to the target site using the `kbd_cron_process` parameter to trigger the backup generation script.
3. The plugin executes the backup routine, dumping the MySQL database into a file within the `/wp-content/uploads/` directory.
4. Attacker monitors the request or estimates the Unix timestamp at the time of execution.
5. Attacker iterates through possible filenames based on the database name and the predictable timestamp and random range.
6. Attacker attempts to download the generated backup file directly via standard web request.
7. Attacker successfully exfiltrates the complete database contents.

## Impact

Successful exploitation leads to the complete exfiltration of the WordPress database. This includes sensitive data such as site administrator credentials, hashed user passwords, configuration files, and PII of registered users. The breach of this data provides an attacker with the necessary information to perform full account takeover or further compromise the hosting environment.

## Recommendation

* Patch the Keep Backup Daily plugin to version 2.1.4 or later immediately across all WordPress installations.
* Deploy the provided Sigma rule to detect attempts to invoke the `kbd_cron_process` parameter from unauthenticated sources.
* Audit web server logs for suspicious access patterns targeting the `/wp-content/uploads/` directory with file extensions indicative of database backups (e.g., .sql, .zip, .sql.gz).
* Implement restrictions on the web server to prevent direct access to sensitive file types within the uploads directory.
