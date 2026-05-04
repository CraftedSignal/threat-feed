---
title: NTDS Dump via Wbadmin
slug: 2024-07-ntds-dump-wbadmin
description: Attackers with Backup Operator privileges may abuse wbadmin.exe to access the NTDS.dit file, enabling credential dumping and domain compromise.
date: "2024-07-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - windows
  - wbadmin
  - ntds.dit
vendors:
  - Microsoft
  - Elastic
  - Crowdstrike
  - SentinelOne
products:
  - Microsoft Defender XDR
  - Elastic Defend
  - CrowdStrike FDR
  - SentinelOne Cloud Funnel
  - Sysmon
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://medium.com/r3d-buck3t/windows-privesc-with-sebackupprivilege-65d2cd1eb960
rules:
  - title: Detect NTDS Dump via Wbadmin Execution
    description: Detects the execution of wbadmin.exe with arguments to access the NTDS.dit file, indicating potential credential dumping.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003.003
    data_sources:
      - process_creation
      - windows
  - title: Detect NTDS Dump via Wbadmin File Access
    description: Detects process accessing the NTDS.dit file
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003.003
    data_sources:
      - file_event
      - windows
rules_count: 2
---

This detection identifies the execution of `wbadmin.exe` with arguments indicative of an attempt to access and dump the NTDS.dit file from a Windows domain controller. Attackers with sufficient privileges, specifically those belonging to groups like Backup Operators, can abuse the legitimate `wbadmin.exe` utility to create a backup of the Active Directory database (NTDS.dit). This file contains sensitive credential information, and once obtained, attackers can extract password hashes and compromise the entire domain. This activity is often part of a larger attack aimed at gaining persistent access and control over the network. The Elastic detection rule was published on 2024-06-05 and last updated on 2026-05-04.

## Attack Chain

1. An attacker gains initial access to a system within the target network. This may be achieved through phishing, exploiting vulnerabilities, or compromised credentials.
2. The attacker escalates privileges to obtain membership in the Backup Operators group or a similar privileged group capable of running backups.
3. The attacker executes `wbadmin.exe` with the `recovery` argument, targeting the NTDS.dit file. The command line includes parameters to create a system state backup.
4. Wbadmin creates a backup of the system state, including the NTDS.dit file, in a specified location.
5. The attacker copies the NTDS.dit file from the backup location to a separate location for offline analysis.
6. The attacker uses tools such as `ntdsutil.exe` or `secretsdump.py` to extract password hashes from the NTDS.dit file.
7. The attacker cracks the password hashes or uses them in pass-the-hash attacks to gain access to other systems and resources within the domain.
8. The attacker achieves domain dominance and persistence, allowing them to control critical systems and data.

## Impact

Successful exploitation allows attackers to dump credentials from the NTDS.dit file, leading to complete compromise of the Active Directory domain. This enables them to move laterally, access sensitive data, and establish persistent control over the environment. The impact can include data breaches, ransomware deployment, and long-term disruption of business operations. The medium risk score indicates that while the attack requires specific privileges, the consequences are significant if successful.

## Recommendation

*   Enable process creation logging with command line arguments to detect `wbadmin.exe` execution as described in the Attack Chain (Data Source: Windows Security Event Logs, Sysmon).
*   Implement the provided Sigma rule to detect suspicious `wbadmin.exe` execution with NTDS.dit related arguments in your SIEM (Rule: NTDS Dump via Wbadmin).
*   Monitor and restrict membership in privileged groups like Backup Operators to minimize the risk of abuse (Reference: https://medium.com/r3d-buck3t/windows-privesc-with-sebackupprivilege-65d2cd1eb960).
*   Review and whitelist legitimate backup schedules or disaster recovery processes to reduce false positives (False positive analysis).
