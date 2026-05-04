---
title: Suspicious Enumeration Commands Spawned via WMIPrvSE
slug: 2024-01-wmiprvse-enumeration
description: This rule detects suspicious execution of system enumeration commands by the Windows Management Instrumentation Provider Service (WMIPrvSE), indicating potential reconnaissance or malicious activity on Windows systems.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - enumeration
  - wmi
  - discovery
  - execution
  - windows
vendors:
  - Microsoft
  - Elastic
  - SentinelOne
  - Crowdstrike
products:
  - Elastic Defend
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
  - Sysmon
affected_os:
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
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/execution_enumeration_via_wmiprvse.toml
rules:
  - title: Enumeration Command Spawned via WMIPrvSE
    description: Detects execution of common Windows enumeration tools spawned by WMIPrvSE.exe, which is indicative of potential reconnaissance activity.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - execution
    techniques:
      - T1047
    data_sources:
      - process_creation
      - windows
  - title: Suspicious net.exe Usage via WMIPrvSE
    description: Detects specific net.exe commands related to user or group enumeration when spawned by WMIPrvSE.exe.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - execution
    techniques:
      - T1047
      - T1087
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers can leverage the Windows Management Instrumentation (WMI) to execute commands for reconnaissance and enumeration within a compromised system. This involves spawning native Windows tools via the WMI Provider Service (WMIPrvSE). This activity is often used to gather system and network information in a stealthy manner, which could be part of a larger attack, such as lateral movement or privilege escalation. This behavior matters because it allows adversaries to gather information about the target environment without using easily detectable methods, potentially leading to further compromise.

## Attack Chain

1.  The attacker gains initial access to a Windows system (e.g., through phishing or exploiting a vulnerability).
2.  The attacker uses WMI to execute a reconnaissance command.
3.  WMIPrvSE.exe is invoked to execute the attacker's specified command.
4.  The attacker executes commands such as `ipconfig.exe`, `net.exe`, or `systeminfo.exe` via WMIPrvSE.exe to gather network configuration details, user information, and system information.
5.  The enumerated information is collected and potentially exfiltrated to a command and control server.
6.  The attacker uses the gathered information to identify further targets within the network.
7.  The attacker moves laterally to other systems using stolen credentials or exploited vulnerabilities.
8.  The attacker achieves their final objective, such as data exfiltration, ransomware deployment, or persistent access.

## Impact

Successful execution of enumeration commands via WMIPrvSE allows attackers to gather sensitive information about the system and network environment. This information can be used to facilitate lateral movement, privilege escalation, and data theft, potentially leading to significant financial loss, reputational damage, and disruption of business operations.

## Recommendation

*   Enable Sysmon process creation logging to capture the execution of enumeration commands (Data Source: Sysmon).
*   Deploy the Sigma rule "Enumeration Command Spawned via WMIPrvSE" to your SIEM to detect suspicious WMIPrvSE activity (Sigma rule).
*   Investigate any instances of WMIPrvSE spawning common enumeration tools such as `net.exe`, `ipconfig.exe`, or `systeminfo.exe` (Sigma rule).
*   Implement network segmentation to limit the scope of potential lateral movement following successful enumeration (Attack Chain).
