---
title: Windows Scheduled Tasks AT Command Enabled via Registry Modification
slug: 2024-01-at-command-enabled
description: Attackers may enable the deprecated Windows AT command via registry modification to achieve local persistence or lateral movement.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - persistence
  - lateral-movement
  - windows
vendors:
  - Microsoft
  - Elastic
  - Crowdstrike
  - SentinelOne
products:
  - Windows
  - Elastic Defend
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
  - Crowdstrike FDR
  - Sysmon
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1053
    technique_name: Scheduled Task/Job
references:
  - https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-scheduledjob
rules:
  - title: Scheduled Tasks AT Command Enabled
    description: Detects attempts to enable the Windows scheduled tasks AT command via registry modification.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1053.002
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Scheduled Tasks AT Command Usage
    description: Detects the use of the AT command to schedule tasks, which may indicate malicious activity.
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1053.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The legacy Windows AT command allows scheduling tasks for execution. While deprecated since Windows 8 and Windows Server 2012, it remains present for backwards compatibility. Attackers may enable the AT command through registry modifications to achieve persistence or lateral movement within a network. This technique bypasses modern security controls and can be difficult to detect without specific monitoring. The detection rule monitors registry changes enabling this command, flagging potential misuse by checking specific registry paths and values indicative of enabling the AT command. The use of this command allows an attacker to execute commands with elevated privileges, potentially compromising the entire system.

## Attack Chain

1. An attacker gains initial access to a system, possibly through phishing or exploiting a vulnerability.
2. The attacker attempts to enable the AT command by modifying the registry.
3. The registry key `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Configuration\EnableAt` is modified to a value of "1" or "0x00000001".
4. The attacker uses the AT command to schedule a malicious task.
5. The scheduled task executes a command or script, such as downloading and executing malware.
6. The malware establishes persistence on the system.
7. The attacker uses the compromised system as a pivot point for lateral movement.

## Impact

Enabling the AT command can lead to unauthorized task scheduling, malware execution, persistence, and lateral movement within a network. Successful exploitation can compromise sensitive data, disrupt operations, and grant attackers persistent access to critical systems. The use of a deprecated command makes it harder to detect, increasing the impact.

## Recommendation

*   Monitor registry events for modifications to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Configuration\EnableAt` as described in the rule overview.
*   Deploy the Sigma rule "Scheduled Tasks AT Command Enabled" to your SIEM and tune for your environment.
*   Enable Sysmon process creation and registry event logging to activate the rule.
*   Investigate any alerts triggered by the Sigma rule "Scheduled Tasks AT Command Enabled" for suspicious activity.
