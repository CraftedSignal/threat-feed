---
title: Adversaries Disabling Important Scheduled Tasks
slug: 2024-01-schtasks-disable
description: Adversaries disable crucial scheduled tasks, such as those related to BitLocker, Windows Defender, System Restore and Windows Update, using schtasks.exe to disrupt services and potentially facilitate data destruction or ransomware deployment.
date: "2024-01-03T15:30:00Z"
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
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1490/T1490.md#atomic-test-8---windows---disable-the-sr-scheduled-task
  - https://twitter.com/MichalKoczwara/status/1553634816016498688
  - https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_schtasks_disable.yml
rules:
  - title: Detect Schtasks Task Disable
    description: Detects when adversaries stop services or processes by disabling their respective scheduled tasks via schtasks.exe in order to conduct data destructive activities
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1489
    data_sources:
      - process_creation
      - windows
  - title: Detect Schtasks Task Change with /disable Parameter
    description: Detects the use of schtasks.exe to modify a scheduled task by using the /change and /disable parameters.
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

Attackers are increasingly targeting scheduled tasks to disable critical system functions. This tactic involves using `schtasks.exe` to disable essential tasks related to security, backup, and update mechanisms. By disabling tasks like Windows Defender scans, System Restore points, BitLocker encryption, and Windows Update, adversaries can significantly weaken a system's defenses, making it more vulnerable to data destruction or ransomware attacks. The observed behavior involves the execution of…
