---
title: Raccine Scheduled Task Deletion via Schtasks
slug: 2024-01-raccine-task-deletion
description: Detection of adversaries deleting the Raccine Rules Updater scheduled task via `schtasks.exe` to disable the ransomware protection tool, potentially leading to data encryption and loss.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - raccine
  - ransomware
  - defense-evasion
  - scheduled-task
  - windows
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
references:
  - https://redcanary.com/blog/blackbyte-ransomware/
  - https://github.com/Neo23x0/Raccine
rules:
  - title: Detect Raccine Scheduled Task Deletion via Schtasks
    description: Detects the deletion of the Raccine Rules Updater scheduled task using schtasks.exe, indicating a potential attempt to disable ransomware protection.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
  - title: Detect Raccine Scheduled Task Deletion - Parent Process
    description: Detects suspicious parent processes spawning schtasks.exe to delete Raccine scheduled tasks, indicating a potential attempt to disable ransomware protection.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This brief focuses on detecting the deletion of the Raccine Rules Updater scheduled task, a critical action that adversaries may take to disable Raccine, a security tool designed to prevent ransomware attacks. The deletion is typically performed using the `schtasks.exe` command. This activity is significant because successful deletion of the Raccine scheduled task allows ransomware to execute unimpeded, leading to potential data encryption and data loss. The detection leverages endpoint detection and response (EDR) agents and focuses on process names and command-line executions to identify this malicious behavior. Defenders should prioritize monitoring for this activity as it often precedes ransomware deployment.

## Attack Chain

1.  Initial compromise of the target system via unspecified means (e.g., phishing, exploitation of public-facing application).
2.  Execution of arbitrary commands on the compromised system.
3.  The adversary uses `schtasks.exe` to query the list of scheduled tasks to identify the Raccine Rules Updater task.
4.  `schtasks.exe` is then used with the `delete` parameter to remove the "Raccine Rules Updater" scheduled task.
5.  The operating system removes the scheduled task entry.
6.  Ransomware is deployed on the system without Raccine's protection.
7.  Ransomware encrypts files on local and network shares.
8.  A ransom note is dropped, demanding payment for decryption.

## Impact

Successful deletion of the Raccine scheduled task can lead to a successful ransomware attack. This can result in data encryption, system downtime, and potential financial losses due to ransom payments or recovery costs. The severity of the impact depends on the extent of the data encryption and the organization's ability to recover from backups. Organizations without Raccine deployed are not directly affected but remain vulnerable to ransomware.

## Recommendation

*   Deploy the provided Sigma rules to detect the execution of `schtasks.exe` deleting tasks containing "Raccine" in the task name or description (`schtasks_raccine_deletion`).
*   Enable process monitoring and command-line logging via Sysmon or similar EDR solutions to ensure visibility into process executions.
*   Investigate any instances of `schtasks.exe` being used to delete scheduled tasks, especially those related to security tools.
*   Review and harden scheduled task permissions to prevent unauthorized modifications.
*   Monitor parent processes of `schtasks.exe` for suspicious activity.
