---
title: Suspicious WerFault Child Process Abuse
slug: 2024-01-09-werfault-child-process
description: This rule detects suspicious child processes of WerFault.exe, a Windows error reporting tool, indicating potential abuse of the SilentProcessExit registry key to execute malicious processes stealthily for defense evasion, persistence, and privilege escalation.
date: "2024-01-09T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - persistence
  - privilege-escalation
  - masquerading
vendors:
  - Microsoft
  - Elastic
  - SentinelOne
products:
  - Microsoft Defender XDR
  - Elastic Defend
  - SentinelOne Cloud Funnel
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1546
    technique_name: Event Triggered Execution
references:
  - https://www.hexacorn.com/blog/2019/09/19/silentprocessexit-quick-look-under-the-hood/
  - https://www.hexacorn.com/blog/2019/09/20/werfault-command-line-switches-v0-1/
  - https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/persistence_SilentProcessExit_ImageHijack_sysmon_13_1.evtx
  - http://web.archive.org/web/20230530011556/https://blog.menasec.net/2021/01/
rules:
  - title: WerFault Child Process Masquerading
    description: Detects suspicious child processes of WerFault.exe with specific command-line arguments used to abuse SilentProcessExit.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
      - privilege_escalation
    techniques:
      - T1036
      - T1546
      - T1546.012
    data_sources:
      - process_creation
      - windows
  - title: WerFault SilentProcessExit Registry Modification
    description: Detects modifications to the SilentProcessExit registry key, often used to hijack WerFault for malicious purposes.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
      - privilege_escalation
    techniques:
      - T1546.012
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

This detection identifies suspicious child processes spawned by WerFault.exe, the Windows Error Reporting tool. Attackers can abuse WerFault by manipulating the `SilentProcessExit` registry key to execute malicious processes. This technique allows for defense evasion, persistence, and privilege escalation. The detection focuses on WerFault processes with specific command-line arguments (`-s`, `-t`, and `-c`) known to be used in SilentProcessExit exploitation, while excluding legitimate executables like `Initcrypt.exe` and `Heimdal.Guard.exe`. The rule helps defenders identify potential attempts to hijack the error reporting mechanism for malicious purposes. The monitored data sources include Windows Event Logs, Sysmon, Elastic Defend, Microsoft Defender XDR, and SentinelOne.

## Attack Chain

1. An attacker gains initial access to the system (e.g., via phishing or exploiting a vulnerability).
2. The attacker modifies the `SilentProcessExit` registry key to specify a malicious process to be executed when a target application crashes. This involves setting the `ReportingMode` and `Debugger` values under the `SilentProcessExit` key for the target application.
3. The attacker triggers a crash in the target application or waits for a legitimate crash to occur.
4. WerFault.exe is invoked to handle the application crash.
5. Due to the registry modification, WerFault.exe spawns the attacker-controlled process, passing command-line arguments such as `-s`, `-t`, and `-c`.
6. The attacker-controlled process executes with the privileges of WerFault.exe, potentially achieving privilege escalation.
7. The malicious process performs actions such as injecting code into other processes, establishing persistence, or exfiltrating data.
8. The attacker achieves their objectives, such as maintaining persistence, escalating privileges, or evading detection.

## Impact

A successful attack can lead to persistence, privilege escalation, and defense evasion. Attackers can use this technique to execute malicious code with elevated privileges, potentially bypassing security controls and gaining unauthorized access to sensitive data and system resources. The number of victims and affected sectors can vary depending on the attacker's objectives and the scope of the initial compromise.

## Recommendation

*   Enable Sysmon process creation logging to capture WerFault.exe child processes (Data Source: Sysmon).
*   Deploy the Sigma rule "WerFault Child Process Masquerading" to your SIEM and tune for your environment.
*   Review the `SilentProcessExit` registry key for unauthorized modifications (registry_set event).
*   Investigate any WerFault.exe processes with command-line arguments `-s`, `-t`, and `-c` (process_creation event).
