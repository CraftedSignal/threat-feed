---
title: Suspicious Enumeration Commands Spawned via WMIPrvSE
slug: 2024-01-wmiprvse-enumeration
description: This rule identifies suspicious activity where enumeration commands are spawned via the Windows Management Instrumentation Provider Service (WMIPrvSE) to gather system and network information.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - windows
  - enumeration
  - wmi
  - reconnaissance
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1047
    technique_name: Windows Management Instrumentation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1007
    technique_name: System Service Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1012
    technique_name: Query Registry
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1033
    technique_name: System Owner/User Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1049
    technique_name: System Network Connections Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1057
    technique_name: Process Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1518
    technique_name: Software Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1615
    technique_name: Group Policy Discovery
references:
  - https://attack.mitre.org/techniques/T1047/
rules:
  - title: Enumeration Command Spawned via WMIPrvSE
    description: Detects native Windows host and network enumeration commands spawned by WMIPrvSE.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - execution
    techniques:
      - T1016
      - T1047
    data_sources:
      - process_creation
      - windows
  - title: Suspicious SC.exe Usage via WMIPrvSE
    description: Detects specific usage patterns of sc.exe (Service Control) spawned via WMIPrvSE that are often indicative of malicious activity.
    platform: sigma
    severity: low
    tactics:
      - execution
      - persistence
    techniques:
      - T1047
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may abuse the Windows Management Instrumentation (WMI) to execute commands for reconnaissance purposes. This involves spawning native Windows host and network enumeration commands via the Windows Management Instrumentation Provider Service (WMIPrvSE). The goal is to gather information about the system and network environment for situational awareness and potential lateral movement. This activity often occurs after initial access and can be a sign of malicious actors attempting to map the network and identify valuable targets. The rule detects execution of enumeration commands such as `arp.exe`, `ipconfig.exe`, and `net.exe` by `wmiprvse.exe`, excluding benign use cases to highlight potentially malicious activity.

## Attack Chain

1.  The attacker gains initial access to a Windows system (e.g., via phishing or exploiting a vulnerability).
2.  The attacker leverages WMI to execute reconnaissance commands. This is achieved by invoking WMIPrvSE to run commands via `Win32_Process` creation.
3.  WMIPrvSE spawns enumeration tools such as `ipconfig.exe` to gather network configuration.
4.  `net.exe` is executed by WMIPrvSE to discover domain users and groups.
5.  `systeminfo.exe` is executed by WMIPrvSE to collect detailed system information, including OS version and installed hotfixes.
6.  `tasklist.exe` is executed to identify running processes on the system.
7.  The gathered information is used to plan further actions, such as lateral movement or privilege escalation.

## Impact

Successful exploitation leads to the attacker gaining detailed knowledge of the target system and network environment. This information can be used to facilitate lateral movement, identify valuable data, and ultimately compromise the organization's assets. The impact includes potential data breaches, system compromise, and disruption of services. If the attacker successfully enumerates the environment, it increases the likelihood of a successful attack campaign.

## Recommendation

*   Implement the provided Sigma rules to detect enumeration commands spawned via WMIPrvSE (`process_creation` logs).
*   Review process command line details to understand the specific enumeration command executed and its arguments, focusing on the process.command_line field.
*   Monitor `process_creation` events with a parent process name of `wmiprvse.exe` for known enumeration tools (e.g., `ipconfig.exe`, `net.exe`, `systeminfo.exe`).
*   Correlate the event with other logs or alerts from the same host to identify any preceding or subsequent suspicious activities, such as lateral movement or privilege escalation attempts.
