---
title: FreePBX Endpoint Manager Unauthenticated Remote Code Execution
slug: 2026-09-freepbx-rce
description: An unauthenticated SQL injection vulnerability (CVE-2025-57819) in the FreePBX Endpoint Manager module allows attackers to achieve remote code execution by injecting malicious cron jobs.
date: "2026-09-03T14:54:16Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:sangoma:freepbx:*:*:*:*:*:*:*:*
tags:
  - webapps
  - cve
  - rce
  - sql-injection
  - exploit
vendors:
  - FreePBX
products:
  - FreePBX (15.x < 15.0.66, 16.x < 16.0.89, 17.x < 17.0.3)
affected_os:
  - Debian
  - Ubuntu
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: CVE-2025-57819 is a critical unauthenticated SQL injection vulnerability discovered in the Endpoint Manager module of FreePBX.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Unix Shell
    evidence: The cron job runs a reverse shell command with administrative privileges.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505.002
    technique_name: 'Server Software Component: Cron Jobs'
    evidence: An attacker can execute an INSERT statement to add a malicious cron job to the cron_jobs table.
    confidence_band: high
cves:
  - id: CVE-2025-57819
    cvss: 9.8
    epss: 0.88269
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-57819
  - https://www.exploit-db.com/exploits/52681
  - https://github.com/FreePBX/security-reporting/security/advisories/GHSA-m42g-xg4c-5f3h
rules:
  - title: Detect CVE-2025-57819 Exploitation Attempt
    description: Detects exploitation attempts against FreePBX Endpoint Manager by searching for SQL injection patterns in the brand parameter of ajax.php
    platform: sigma
    severity: critical
    tactics:
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
    - action: Patch FreePBX to versions 15.0.66, 16.0.89, or 17.0.3
      owner: IT Operations
      due: 24h
      evidence: Source advisory states fixed versions
  hunt_leads:
    - lead: Search cron_jobs table in database for anomalous entries
      technique_id: T1505.002
      data_needed:
        - Database query logs or direct SQL inspection
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attacker injects cron job via SQLi
  mitigation_plan:
    - priority: immediate
      action: Firewall off web access to /admin/ajax.php
      owner: IT Operations
      addresses: CVE-2025-57819
      evidence: Vulnerability is unauthenticated
---

FreePBX is vulnerable to a critical unauthenticated remote code execution (RCE) vulnerability, tracked as CVE-2025-57819, affecting versions prior to 15.0.66, 16.0.89, and 17.0.3. The vulnerability resides in the Endpoint Manager module's 'brand' parameter within the '/admin/ajax.php' endpoint. Because the application fails to properly sanitize user input before incorporating it into SQL queries, an unauthenticated attacker can perform stacked SQL injection attacks. By leveraging this flaw, an attacker can insert arbitrary entries into the 'cron_jobs' table of the underlying database. These entries are periodically executed by the system's cron daemon with administrative privileges, typically as the Apache web server user, resulting in full remote code execution on the server. The availability of weaponized exploit code in the public domain necessitates immediate patching.

## Attack Chain

1. The attacker identifies an internet-facing FreePBX server running a vulnerable version of the Endpoint Manager module.
2. The attacker sends a crafted GET request to '/admin/ajax.php' targeting the 'brand' parameter.
3. The crafted input performs SQL injection to bypass authentication or validation routines using stacked queries.
4. The attacker executes a SQL 'INSERT' statement to add a new task to the 'cron_jobs' table.
5. The injected command is configured as a reverse shell payload encoded in base64.
6. The system's cron daemon processes the malicious entry within approximately 60 seconds.
7. The system executes the base64-decoded bash command with the privileges of the web server user.
8. A reverse shell is established, granting the attacker interactive command execution on the host.

## Impact

Successful exploitation of CVE-2025-57819 leads to complete server compromise. As the malicious cron job executes with the privileges of the web server user, attackers can gain persistent access, exfiltrate sensitive configuration data, or pivot into the internal network where the FreePBX instance is hosted. This vulnerability is reported to be included in CISA's Known Exploited Vulnerabilities catalog.

## Recommendation

Prioritized actions for security teams:
- Patch all affected FreePBX instances immediately: update to 15.0.66, 16.0.89, 17.0.3, or later versions.
- Deploy the provided Sigma rule to monitor for suspicious requests to '/admin/ajax.php' containing SQL injection patterns.
- Audit the 'cron_jobs' table in the FreePBX database for any unauthorized or suspicious command entries.
- Restrict access to the FreePBX web management interface to trusted internal networks via firewall rules to mitigate exploitation attempts.
