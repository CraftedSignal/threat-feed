---
title: Detection of System Information Discovery Techniques
slug: 2024-01-02-system-info-discovery
description: This brief covers the detection of adversaries using native Windows commands like `wmic qfe`, `systeminfo`, and `hostname` to gather system information for further exploitation.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - system-discovery
  - windows
  - post-exploitation
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
references:
  - https://web.archive.org/web/20210119205146/https://oscp.infosecsanyam.in/priv-escalation/windows-priv-escalation
rules:
  - title: Detect System Information Discovery
    description: Detects the execution of common system information discovery commands such as wmic qfe, systeminfo, and hostname.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

This detection focuses on identifying the use of system information discovery techniques by adversaries on Windows systems. Attackers commonly use commands such as `wmic qfe`, `systeminfo`, and `hostname` to enumerate system details like installed software, hardware configuration, and network information. This reconnaissance activity allows them to tailor subsequent attacks, identify vulnerabilities, and potentially escalate privileges or move laterally within the network. The detection leverages Endpoint Detection and Response (EDR) data, specifically process execution logs, to identify suspicious usage patterns of these commands. Monitoring for these activities can help defenders identify early stages of an attack and prevent further compromise. This analytic was last updated in March 2026.

## Attack Chain

1.  **Initial Access:** The attacker gains initial access to the system via unspecified means.
2.  **Command Execution:** The attacker executes `wmic qfe` to gather a list of installed Quick Fix Engineering (QFE) updates, revealing patch levels.
3.  **System Enumeration:** The attacker executes `systeminfo` to collect detailed system configuration information, including OS version, installed hotfixes, and hardware details.
4.  **Hostname Discovery:** The attacker executes `hostname` to identify the system's hostname, aiding in network mapping.
5.  **Data Aggregation:** The attacker aggregates the collected system information to identify potential vulnerabilities or misconfigurations.
6.  **Privilege Escalation:** Based on the gathered information, the attacker attempts to exploit identified vulnerabilities to escalate privileges.
7.  **Lateral Movement:** The attacker uses the gathered information to identify other vulnerable systems within the network and move laterally.
8.  **Objective Completion:** The attacker achieves their final objective, such as data exfiltration, deploying ransomware, or establishing persistence.

## Impact

Successful exploitation following system information discovery can lead to significant damage. Attackers can use the gathered information to escalate privileges, move laterally to other systems, and ultimately exfiltrate sensitive data, deploy ransomware, or establish long-term persistence. Identifying these techniques early is critical to prevent significant compromise.

## Recommendation

*   Deploy the Sigma rule "Detect System Information Discovery" to your SIEM, focusing on `process_creation` logs from Windows systems (Sysmon EventID 1, Windows Event Log Security 4688, CrowdStrike ProcessRollup2).
*   Tune the Sigma rule by filtering out known-good processes or administrative accounts that legitimately use these commands for system maintenance.
*   Enable command-line logging for process creation events via Sysmon or Windows Event Logging to ensure the detection has the necessary data to function effectively.
