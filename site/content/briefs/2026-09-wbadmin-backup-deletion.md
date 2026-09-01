---
title: Destructive Deletion of System Backups via Wbadmin.exe
slug: 2026-09-wbadmin-backup-deletion
description: Adversaries utilize the legitimate Windows Backup utility to delete system and state backups as a destructive measure to inhibit recovery during ransomware operations.
date: "2026-09-01T12:08:57Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ransomware
  - defense-evasion
  - backup-tampering
affected_os:
  - Windows Server
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: This technique is used by numerous ransomware families and actors.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_wbadmin_delete_all_backups.yml
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin-delete-systemstatebackup
rules:
  - title: Detect All Backups Deleted Via Wbadmin.EXE
    description: Detects the deletion of all backups or system state backups via wbadmin.exe, a technique frequently used by ransomware to prevent recovery.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Source provides concrete detection logic
  mitigation_plan:
    - priority: medium_term
      action: Implement immutable backup solution
      owner: IT Operations
      addresses: T1490
      evidence: Preventing reliance on mutable system-level backups
---

Adversaries frequently target Windows backup utilities to perform destructive operations, aiming to eliminate recovery options before deploying ransomware. This specific technique involves the misuse of the built-in Windows utility `wbadmin.exe` to delete system or state backups. By executing specific command-line arguments, attackers can effectively wipe existing backup snapshots. This behavior is commonly observed across various ransomware families, such as LockBit and Avaddon, as part of their impact phase to ensure victim organizations cannot restore data without engaging the attackers. Monitoring for these specific `wbadmin` commands provides a high-fidelity signal for detecting potential pre-encryption activity in server environments where Windows Backup is enabled.

## Attack Chain

1. Initial access is established via exploitation or credential theft.
2. The attacker gains elevated privileges to run administrative utilities.
3. The attacker locates the Windows backup repository.
4. The attacker initiates the `wbadmin.exe` utility via the command line.
5. The attacker specifies the `delete` command with flags to target system or state backups.
6. The `keepVersions:0` argument is passed to ensure all existing backup versions are purged.
7. The system process executes the backup deletion command, rendering local recovery points inaccessible.
8. The attacker proceeds to encrypt the file system to finalize the extortion attempt.

## Impact

Successful execution of this technique prevents an organization from recovering their data using standard Windows backup features. This significantly increases the leverage of ransomware actors, as the lack of local backups leaves the organization with no viable path to data restoration, often forcing victims to consider paying the ransom.

## Recommendation

- Deploy the Sigma rule below to detect unauthorized usage of `wbadmin.exe` for backup deletion.
- Enable Sysmon or Windows Event Log (Event ID 4688) process-creation logging to capture the full command line of `wbadmin.exe`.
- Audit administrative access to servers hosting backup repositories to minimize the risk of unauthorized utility execution.
- Establish offline or immutable backup storage that is not accessible via standard system-level administrative commands.
