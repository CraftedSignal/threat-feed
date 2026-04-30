---
title: Multiple Critical Vulnerabilities in Veeam Backup & Replication Allow Remote Code Execution
slug: 2026-03-veeam-rce
description: Multiple critical vulnerabilities in Veeam Backup & Replication, including CVE-2026-21666, CVE-2026-21668, CVE-2026-21669, CVE-2026-21670, CVE-2026-21671, CVE-2026-21672, and CVE-2026-21708, allow for remote code execution, privilege escalation, and arbitrary file manipulation by authenticated users, potentially leading to a complete compromise of the backup infrastructure.
date: "2026-03-14T10:00:00Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - veeam
  - rce
  - vulnerability
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
references:
  - https://ccb.belgium.be/advisories/warning-multiple-critical-vulnerabilities-veeam-backup-replication-patch-immediately
  - https://www.veeam.com/kb4830
  - https://www.veeam.com/kb4831
  - https://nvd.nist.gov/vuln/detail/CVE-2026-21666
  - https://nvd.nist.gov/vuln/detail/CVE-2026-21668
  - https://nvd.nist.gov/vuln/detail/CVE-2026-21669
  - https://nvd.nist.gov/vuln/detail/CVE-2026-21670
  - https://nvd.nist.gov/vuln/detail/CVE-2026-21671
  - https://nvd.nist.gov/vuln/detail/CVE-2026-21672
  - https://nvd.nist.gov/vuln/detail/CVE-2026-21708
rules:
  - title: Detect Veeam Backup Repository File Manipulation
    description: Detects attempts to manipulate files within the Veeam Backup Repository, potentially indicating exploitation of CVE-2026-21668.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1078
    data_sources:
      - file_event
      - windows
  - title: Detect Suspicious Processes Spawned by Veeam Executables
    description: Detects the creation of suspicious processes (e.g., cmd.exe, powershell.exe) by Veeam executables, which could indicate exploitation of RCE vulnerabilities like CVE-2026-21666, CVE-2026-21669, and CVE-2026-21671.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On March 13, 2026, the Centre for Cybersecurity Belgium (CCB) issued an advisory regarding multiple critical vulnerabilities affecting Veeam Backup & Replication versions 12.3.2.4165 and earlier, as well as version 13.0.1.1071. These vulnerabilities, including CVE-2026-21666, CVE-2026-21668, CVE-2026-21669, CVE-2026-21670, CVE-2026-21671, CVE-2026-21672, and CVE-2026-21708, can be exploited by authenticated domain users or low-privileged users to achieve remote code execution, bypass…
