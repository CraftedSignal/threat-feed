---
title: Detection of Important Scheduled Task Deletion or Disablement
slug: 2024-01-scheduled-task-deletion
description: Adversaries delete or disable critical scheduled tasks, such as those related to system restore, Windows Defender, BitLocker, Windows Backup, or Windows Update, to disrupt operations and potentially conduct data destructive activities.
date: "2024-01-03T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - attack.execution
  - attack.privilege-escalation
  - attack.persistence
  - attack.t1053.005
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1053
    technique_name: Scheduled Task/Job
references:
  - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4699
  - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4701
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_susp_scheduled_task_delete_or_disable.yml
rules:
  - title: Suspicious Scheduled Task Deletion/Disablement of Critical Tasks
    description: Detects the deletion or disabling of important scheduled tasks based on Event ID and Task Name.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
      - privilege-escalation
    techniques:
      - T1053.005
    data_sources:
      - windows
      - security
  - title: Scheduled Task Deletion via Schtasks.exe
    description: Detects the execution of schtasks.exe to delete scheduled tasks, which may indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This brief focuses on the detection of malicious activity related to the deletion or disabling of important scheduled tasks within a Windows environment. Adversaries may target these tasks to disrupt normal system operations, escalate privileges, establish persistence, or facilitate data destruction. The targeted tasks often include critical system functions like System Restore, Windows Defender updates, BitLocker encryption, Windows Backup processes, and Windows Update mechanisms. This…
