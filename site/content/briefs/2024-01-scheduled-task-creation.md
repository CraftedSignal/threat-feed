---
title: Scheduled Task Created or Deleted via Command Line
slug: 2024-01-scheduled-task-creation
description: Detection of scheduled task creation or deletion via command-line, often used for persistence and privilege escalation by threat actors.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege_escalation
  - scheduled_task
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1053
    technique_name: Scheduled Task/Job
rules:
  - title: Scheduled Task Creation via Command Line
    description: Detects the creation of scheduled tasks using schtasks.exe via command line.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
  - title: Scheduled Task Deletion via Command Line
    description: Detects the deletion of scheduled tasks using schtasks.exe via command line.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This brief focuses on the detection of scheduled task creation or deletion events triggered through command-line interfaces on Windows systems. While the provided document lacks specific details on a particular threat actor or campaign, the technique of creating and deleting scheduled tasks programmatically is a common tactic used by various threat actors for persistence, privilege escalation, and lateral movement. Attackers often leverage tools like `schtasks.exe` to automate malicious activities. Monitoring for these actions is crucial for detecting suspicious behavior, even without specific threat intelligence context. This generic but important technique helps identify anomalous system administration activities that could lead to further compromise.

## Attack Chain

1.  Attacker gains initial access through an exploit or compromised credentials.
2.  Attacker uses `cmd.exe` or PowerShell to execute commands.
3.  The attacker utilizes `schtasks.exe` to create a new scheduled task.
4.  The scheduled task is configured to execute a malicious payload at a specific time or event.
5.  The malicious payload executes with the privileges of the account under which the task runs.
6.  The attacker may use the scheduled task to establish persistence on the system.
7.  The attacker may delete the task after execution to remove evidence.
8.  The attacker achieves their objective, which could include data theft, malware installation, or system compromise.

## Impact

Successful exploitation could lead to persistent access within the environment. Attackers can use the scheduled tasks to execute malicious commands repeatedly, bypass security measures, and maintain control over the compromised system. This can result in data breaches, system instability, and significant operational disruption. If an attacker gains SYSTEM privileges through a scheduled task, they could compromise the entire domain.

## Recommendation

*   Enable process creation logging, specifically monitoring for `schtasks.exe` execution, to activate the rules below.
*   Deploy the Sigma rules in this brief to your SIEM to detect suspicious scheduled task activity.
