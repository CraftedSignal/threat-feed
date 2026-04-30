---
title: Iperius Backup 6.1.0 Privilege Escalation via Malicious Backup Jobs (CVE-2019-25608)
slug: 2026-03-iperius-backup-privilege-escalation
description: Iperius Backup 6.1.0 is vulnerable to privilege escalation, allowing low-privilege users to execute arbitrary programs with elevated privileges by creating malicious backup jobs that execute pre- or post-backup scripts with SYSTEM privileges.
date: "2026-03-23T15:00:00Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - privilege escalation
  - cve-2019-25608
  - iperius backup
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25608
  - https://www.exploit-db.com/exploits/46863
  - https://www.iperiusbackup.com/
  - https://www.iperiusbackup.com/download.aspx
  - https://www.vulncheck.com/advisories/iperius-backup-privilege-escalation-via-backup-job
rules:
  - title: Suspicious Process Spawned by Iperius Backup Service
    description: Detects suspicious processes spawned by the Iperius Backup service, which could indicate exploitation of CVE-2019-25608.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1543.003
    data_sources:
      - process_creation
      - windows
  - title: Iperius Backup Service Running Suspicious Command
    description: Detects the Iperius Backup service executing suspicious commands, potentially indicating CVE-2019-25608 exploitation.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1059.001
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Iperius Backup 6.1.0 is susceptible to a privilege escalation vulnerability (CVE-2019-25608) that enables unprivileged users to gain elevated permissions on the system. This flaw allows attackers to create and configure backup jobs to execute arbitrary code, such as batch files or executable programs, with the privileges of the Iperius Backup Service account, which typically runs as Local System or Administrator. The vulnerability stems from insufficient checks on the scripts or programs…
