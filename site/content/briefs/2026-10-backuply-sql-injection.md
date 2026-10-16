---
title: CVE-2026-93953 - Second-Order SQL Injection in Backuply WordPress Plugin
slug: 2026-10-backuply-sql-injection
description: The Backuply plugin for WordPress is vulnerable to second-order SQL injection, allowing authenticated attackers to achieve privilege escalation through malicious backup restoration.
date: "2026-10-16T04:24:30Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:backuply:backuply:*:*:*:*:*:wordpress:*:*
tags:
  - web-vulnerability
  - wordpress
  - sql-injection
  - privilege-escalation
vendors:
  - Backuply
products:
  - Backuply (<= 1.5.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Backuply – Backup, Restore, Migrate and Clone plugin for WordPress is vulnerable to SQL Injection via the Biographical Info field.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for authenticated attackers... to update the default_role option in wp_options to administrator... resulting in privilege escalation and full site takeover.
    confidence_band: high
cves:
  - id: CVE-2026-93953
    cvss: 8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93953
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update Backuply plugin to the latest patched version
      owner: IT Operations
      due: 24h
      evidence: Source identifies vulnerability in versions <= 1.5.8
  hunt_leads:
    - lead: Search for unexpected Administrator-level account creations
      technique_id: T1098
      data_needed:
        - WordPress user registration logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Injection allows updating default_role to administrator
  mitigation_plan:
    - priority: immediate
      action: Patch plugin and audit wp_options
      owner: IT Operations
      addresses: CVE-2026-93953
      evidence: NVD vulnerability report
---

CVE-2026-93953 is a second-order SQL injection vulnerability affecting the Backuply - Backup, Restore, Migrate and Clone plugin for WordPress, impacting all versions up to and including 1.5.8. The vulnerability arises from improper escaping and insufficient preparation of SQL queries when handling user-supplied input, specifically within the Biographical Info field stored in the wp_usermeta table. An authenticated attacker with subscriber-level access can inject malicious SQL payloads into this field, which the plugin subsequently exports verbatim into a backup SQL dump file. When an administrator restores this crafted backup, the payload escapes the intended INSERT statement, executing arbitrary SQL commands with full database privileges. This exploitation chain enables attackers to modify database records, such as changing the default_role option to administrator and enabling open user registration, ultimately leading to unauthorized administrative access and full site takeover.

## Attack Chain

1. Attacker authenticates to the WordPress site with subscriber-level credentials.
2. Attacker updates their profile Biographical Info field with a crafted SQL injection payload.
3. The Backuply plugin executes a backup process, writing the malicious payload into a SQL dump file within the wp_usermeta insert statements.
4. The attacker waits for an administrator to perform a site restore operation using the malicious backup file.
5. The plugin reads the backup file and executes the INSERT statement, triggering the injection payload during the restoration process.
6. The injected SQL executes with database-level privileges, updating the wp_options table.
7. The attacker modifies the 'default_role' to 'administrator' and sets 'users_can_register' to '1'.
8. Attacker or an automated bot registers a new account, which is automatically granted administrative privileges, resulting in full site takeover.

## Impact

Successful exploitation results in full site takeover and unauthorized privilege escalation. Attackers can gain administrative control, potentially leading to total site compromise, data exfiltration, or defacement. Given the broad use of backup plugins in the WordPress ecosystem, this vulnerability poses a high risk to any site using Backuply version 1.5.8 or earlier.

## Recommendation

* Immediately update the Backuply plugin to the version containing the patch for CVE-2026-93953.
* Review site administrative accounts for suspicious user accounts created via open registration.
* Audit the wp_options table for unauthorized changes to the 'default_role' and 'users_can_register' settings.
* Monitor database error logs for SQL syntax errors related to unexpected input in meta fields.
