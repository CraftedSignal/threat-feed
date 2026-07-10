---
title: Wbadmin Backup Catalog Deletion
slug: 2024-01-wbadmin-backup-deletion
description: Adversaries may delete Windows backup catalogs using wbadmin.exe to inhibit system recovery, often as part of ransomware or other destructive attacks.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - impact
  - backup-deletion
  - ransomware
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://attack.mitre.org/techniques/T1485/
  - https://attack.mitre.org/techniques/T1490/
rules:
  - title: Wbadmin Catalog Deletion
    description: Detects the use of wbadmin.exe to delete the backup catalog.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - process_creation
      - windows
  - title: Wbadmin Systemstatebackup Deletion
    description: Detects the use of wbadmin.exe to delete systemstatebackup.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers, particularly ransomware groups, often attempt to delete or impair backups to prevent victims from recovering their systems without paying a ransom. One method to achieve this is by using the `wbadmin.exe` utility, a legitimate Windows tool used for backup and recovery. Specifically, attackers use `wbadmin.exe` to delete the backup catalog, which contains details about backup volumes and locations. This action directly hinders the recovery process and increases the likelihood of a successful ransomware attack. This technique has been observed across various ransomware incidents targeting Windows environments. Detecting the use of `wbadmin.exe` for deleting backup catalogs is crucial for identifying potential ransomware preparation or ongoing destructive activity. The detection logic leverages process monitoring to identify specific command-line arguments associated with backup deletion activities.

## Attack Chain

1.  The attacker gains initial access to the Windows system through various means such as phishing, exploiting vulnerabilities, or using compromised credentials.
2.  The attacker executes `wbadmin.exe` with administrative privileges.
3.  The attacker uses the `delete catalog` command to remove the backup catalog, which contains information about available backups.
4.  The attacker may also use the `delete systemstatebackup` command to remove system state backups.
5.  The attacker uses the `delete backup` command to remove specific backups.
6.  The attacker disables or deletes shadow copies using `vssadmin.exe` or PowerShell to further prevent recovery.
7.  The attacker deploys and executes ransomware to encrypt data.
8.  The attacker demands ransom for decryption, knowing that system recovery is significantly hampered.

## Impact

The successful deletion of backup catalogs using `wbadmin.exe` can have a significant impact on an organization. Victims are left with limited or no options for system recovery, potentially leading to extended downtime, data loss, and financial repercussions. This technique is often employed as a precursor to ransomware attacks, increasing the likelihood of ransom payment. Organizations that do not detect and prevent this activity are more vulnerable to the damaging effects of ransomware.

## Recommendation

*   Deploy the Sigma rule "Backup Deletion with Wbadmin" to your SIEM and tune for your environment to detect malicious use of `wbadmin.exe`.
*   Monitor process creation events for `wbadmin.exe` with arguments related to deleting catalogs or backups.
*   Investigate any instances of `wbadmin.exe` being executed with delete arguments by unusual accounts or processes.
*   Review and enforce the principle of least privilege to limit the number of accounts that can execute `wbadmin.exe`.
*   Implement robust backup strategies, including offsite backups, to ensure data can be recovered even if local backups are compromised.
