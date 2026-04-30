---
title: Deletion of Critical Scheduled Tasks
slug: 2024-01-03-schtasks-deletion
description: Adversaries delete critical scheduled tasks, such as those related to BitLocker, ExploitGuard, System Restore, Windows Defender, and Windows Update, to disrupt security measures and enable data destruction.
date: "2024-01-03T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - attack.impact
  - attack.t1489
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1489
    technique_name: Service Stop
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_schtasks_delete.yml
rules:
  - title: Detect Deletion of Critical Scheduled Tasks via schtasks.exe
    description: Detects the use of schtasks.exe to delete scheduled tasks associated with critical Windows functions like BitLocker, ExploitGuard, System Restore, Windows Defender, and Windows Update.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1489
    data_sources:
      - process_creation
      - windows
  - title: Detect Deletion of Scheduled Tasks via schtasks.exe (Generic)
    description: Detects the use of schtasks.exe with the delete parameter.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1489
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may attempt to delete scheduled tasks to disable security mechanisms or prevent system recovery, creating an environment conducive to data destruction. This involves using the `schtasks.exe` utility to remove scheduled tasks related to critical system functions. This activity is designed to impair incident response, prevent restoration of systems, and generally increase the impact of an attack. This is done by removing the scheduled tasks, which prevents the execution of security…
