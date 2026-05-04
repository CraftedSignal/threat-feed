---
title: Scheduled Task Creation via Scripting
slug: 2024-01-03-scheduled-task-scripting
description: Detection of scheduled task creation by Windows scripting engines like cscript.exe, wscript.exe, or powershell.exe, used by adversaries to establish persistence on compromised systems.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - scheduled-task
  - windows
vendors:
  - Microsoft
  - Elastic
products:
  - Elastic Defend
  - Sysmon
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_local_scheduled_task_scripting.toml
  - https://attack.mitre.org/techniques/T1053/
  - https://attack.mitre.org/techniques/T1053/005/
  - https://attack.mitre.org/techniques/T1059/
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1059/005/
rules:
  - title: Scheduled Task Creation by PowerShell
    description: Detects the creation of scheduled tasks via PowerShell, a common technique for establishing persistence.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    techniques:
      - T1053.005
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Scheduled Task Actions Registry Modification
    description: Detects modifications to the Scheduled Task Actions registry key, often indicative of malicious task creation or modification.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - registry_set
      - windows
  - title: Script Loading Taskschd.dll
    description: Detects scripting engines loading taskschd.dll, which indicates an attempt to interact with the Task Scheduler service.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    techniques:
      - T1053.005
      - T1059
    data_sources:
      - image_load
      - windows
rules_count: 3
---

This rule detects the creation of scheduled tasks by Windows scripting engines, a tactic commonly employed by adversaries to establish persistence on compromised systems. The activity involves monitoring registry changes related to scheduled task actions and correlating them with script execution. Specifically, it looks for instances where cscript.exe, wscript.exe, powershell.exe, pwsh.exe or powershell_ise.exe are used to create or modify scheduled tasks. This behavior can be indicative of malicious activity, as legitimate software installations should not typically involve scripting engines directly creating scheduled tasks. Defenders should investigate any instances of this behavior to determine if it is malicious. The rule focuses on Windows environments.

## Attack Chain

1.  An attacker gains initial access to the system through various means (e.g., phishing, exploit).
2.  The attacker executes a script (e.g., PowerShell, VBScript) on the target system.
3.  The script interacts with the `taskschd.dll` library to create or modify a scheduled task.
4.  The script modifies the registry key `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\*\Actions` or `\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\*\Actions` to define the actions performed by the scheduled task.
5.  The scheduled task is configured to execute a malicious payload at a specific time or event.
6.  The scheduled task executes, providing the attacker with persistent access to the system.
7.  The attacker leverages the persistent access to perform further malicious activities, such as lateral movement or data exfiltration.

## Impact

Successful exploitation leads to persistence on the compromised system, allowing attackers to maintain access even after reboots or user logoffs. This can facilitate long-term data theft, deployment of ransomware, or further compromise of the network. The impact depends on the privileges of the account under which the scheduled task runs, potentially granting SYSTEM level access.

## Recommendation

*   Enable Sysmon ImageLoad events (Event ID 7) to detect when `taskschd.dll` is loaded by scripting engines (powershell.exe, cscript.exe, wscript.exe) as described in the [Sysmon Event ID 7 setup guide](https://ela.st/sysmon-event-7-setup).
*   Enable Sysmon Registry Events to monitor changes to the registry paths associated with scheduled task actions as described in the [Sysmon Registry Events setup guide](https://ela.st/sysmon-event-reg-setup).
*   Deploy the provided Sigma rules to your SIEM to detect scheduled task creation by scripting engines and tune for your environment.
*   Investigate any alerts generated by these rules, focusing on the specific scripts and scheduled tasks involved.
