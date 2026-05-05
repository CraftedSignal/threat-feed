---
title: Windows Registry Deletion of Scheduled Task Security Descriptor
slug: 2024-01-registry-task-sd-deletion
description: Attackers may delete a scheduled task's Security Descriptor (SD) from the registry to remove evidence of the task for defense evasion.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - persistence
  - windows
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1053
    technique_name: Scheduled Task/Job
references:
  - https://www.microsoft.com/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/
  - https://gist.github.com/MHaggis/5f7fd6745915166fc6da863d685e2728
  - https://gist.github.com/MHaggis/b246e2fae6213e762a6e694cabaf0c17
rules:
  - title: Detect Suspicious Registry SD Deletion
    description: Detects a process deleting the SD value or key in the registry path of a scheduled task, which may indicate defense evasion.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1053.005
    data_sources:
      - registry_set
      - windows
  - title: Detect Deletion of Task Security Descriptor Value
    description: This analytic detects a process attempting to delete a scheduled task's Security Descriptor (SD) value.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1053.005
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

Attackers may attempt to delete a scheduled task's Security Descriptor (SD) from the Windows Registry to evade detection and maintain persistence. This technique involves modifying registry entries associated with scheduled tasks to remove evidence of their existence or configuration. By targeting the SD value, attackers aim to disrupt auditing and monitoring mechanisms that rely on access control information. The observed behavior involves privileged access and is often seen as a post-exploitation tactic to hide malicious activities. Successful execution of this technique allows attackers to maintain covert control over compromised systems. This behavior was described in a Microsoft blog post about the Tarrask malware, which used scheduled tasks for defense evasion.

## Attack Chain

1. An attacker gains initial access to a Windows system through exploitation of a vulnerability or compromised credentials.
2. The attacker elevates privileges to SYSTEM to perform registry modifications.
3. The attacker identifies the registry path of a scheduled task they want to conceal (e.g., `HKLM\System\CurrentControlSet\Services\Schedule\TaskCache\Tree\<TaskName>`).
4. The attacker uses a tool like `reg.exe` or PowerShell to delete the "SD" value or "SD" key from the scheduled task's registry entry.
5. The deletion of the SD removes security descriptor information associated with the scheduled task.
6. This action can hinder security tools and administrators from detecting the task and its associated malicious activity.
7. The attacker continues to use the scheduled task for persistence or other malicious purposes, now with a reduced risk of detection.

## Impact

The deletion of scheduled task Security Descriptors can severely impair the ability to detect and respond to malicious activity. By removing access control information, attackers can effectively hide their persistence mechanisms. Successful execution of this technique can lead to long-term compromise of systems and networks, enabling data theft, ransomware deployment, or other malicious objectives.

## Recommendation

*   Enable Sysmon Event ID 12 logging to capture registry modification events, specifically targeting deletions (data_source).
*   Deploy the Sigma rule `Detect Suspicious Registry SD Deletion` to your SIEM and tune for your environment.
*   Investigate any registry deletions under `HKLM\System\CurrentControlSet\Services\Schedule\TaskCache\Tree\` performed by the SYSTEM user, focusing on entries named "SD" (search).
*   Consider enabling additional auditing for registry key deletions related to scheduled tasks.
