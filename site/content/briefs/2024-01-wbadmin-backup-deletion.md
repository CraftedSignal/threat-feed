---
title: Windows Backup Deletion via Wbadmin
slug: 2024-01-wbadmin-backup-deletion
description: Adversaries may delete Windows backup catalogs and system state backups using wbadmin.exe to inhibit system recovery, often as part of ransomware or other destructive attacks.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - impact
  - backup-deletion
  - windows
vendors:
  - Microsoft
  - Elastic
  - Crowdstrike
  - SentinelOne
products:
  - Microsoft Defender XDR
  - Elastic Defend
  - CrowdStrike Falcon
  - SentinelOne Cloud Funnel
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
references:
  - https://attack.mitre.org/techniques/T1485/
  - https://attack.mitre.org/techniques/T1490/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/impact_deleting_backup_catalogs_with_wbadmin.toml
rules:
  - title: Wbadmin Backup Catalog Deletion
    description: Detects the execution of wbadmin.exe to delete backup catalogs, a common tactic used by ransomware.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
      - T1490
    data_sources:
      - process_creation
      - windows
  - title: Wbadmin System State Backup Deletion
    description: Detects the execution of wbadmin.exe to delete system state backups, a tactic used to inhibit system recovery.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
      - T1490
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers, including ransomware groups, often attempt to remove or impair an organization's ability to recover from an attack. One method to achieve this is by deleting Windows backup catalogs and system state backups using the `wbadmin.exe` utility. Windows Server Backup stores details about backups (what volumes are backed up and where the backups are located) in a backup catalog. Removing these catalogs renders backups unusable for recovery, increasing the impact of the attack. This technique is frequently observed in ransomware playbooks and other destructive attacks targeting Windows environments. This activity can be detected using endpoint detection and response (EDR) solutions, Windows Security Event Logs, and Sysmon.

## Attack Chain

1. The attacker gains initial access to the system via phishing, exploiting a vulnerability, or using compromised credentials.
2. The attacker escalates privileges to administrator level to execute wbadmin.exe.
3. The attacker executes `wbadmin.exe` with the `delete catalog` command to remove backup catalogs.
4. The attacker executes `wbadmin.exe` with the `delete systemstatebackup` command to remove system state backups.
5. The attacker may also delete shadow copies using `vssadmin.exe` or `wmic.exe` to further hinder recovery.
6. The attacker deploys ransomware or initiates other destructive actions.
7. The attacker encrypts or destroys data on the system and connected network shares.
8. The attacker demands a ransom payment for data recovery, which is complicated by the deleted backups.

## Impact

Successful deletion of backup catalogs and system state backups significantly impairs an organization's ability to recover from a ransomware attack or other destructive event. This can lead to prolonged downtime, data loss, and financial losses associated with incident response and recovery efforts. While the number of direct victims of this specific technique is difficult to quantify, the impact is typically observed in conjunction with broader ransomware campaigns affecting organizations across various sectors.

## Recommendation

*   Enable Sysmon process creation logging with Event ID 1 to capture `wbadmin.exe` executions and activate the first Sigma rule.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
*   Monitor Windows Security Event Logs for process creation events related to `wbadmin.exe`.
*   Investigate any instances of `wbadmin.exe` executing with `delete` arguments.
*   Review and harden account access controls to prevent unauthorized use of `wbadmin.exe`.
