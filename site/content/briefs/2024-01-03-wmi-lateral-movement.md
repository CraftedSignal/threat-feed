---
title: WMI Incoming Lateral Movement
slug: 2024-01-03-wmi-lateral-movement
description: Detection of processes executed via Windows Management Instrumentation (WMI) on a remote host indicating potential adversary lateral movement.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lateral-movement
  - wmi
  - windows
vendors:
  - Microsoft
  - HP
  - Nessus
products:
  - HPWBEM
  - SCCM
  - Windows Management Instrumentation
  - .NET Framework
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1047
    technique_name: Windows Management Instrumentation
references:
  - https://attack.mitre.org/techniques/T1021/
  - https://attack.mitre.org/techniques/T1021/003/
  - https://attack.mitre.org/techniques/T1047/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/lateral_movement_incoming_wmi.toml
rules:
  - title: WMI Incoming Connection to Port 135
    description: Detects incoming network connections to port 135, a common port used by WMI for RPC, which can indicate lateral movement.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.003
    data_sources:
      - network_connection
      - windows
  - title: Suspicious Process Spawned by WmiPrvSE.exe
    description: Detects processes spawned by WmiPrvSE.exe (WMI Provider Host) that are not running with System integrity level, which may indicate malicious WMI activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1047
    data_sources:
      - process_creation
      - windows
  - title: WMI Executing Uncommon Tools
    description: Detects specific executables often abused by attackers, when executed via WMI.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1047
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This threat brief focuses on the detection of lateral movement within a Windows environment via Windows Management Instrumentation (WMI). WMI, a core Windows feature, is often exploited by adversaries to remotely execute processes, bypassing traditional security measures. This activity is detected by monitoring network connections and process executions, while filtering out common false positives associated with legitimate administrative use, security tools, and system processes. The goal is to highlight potential threats indicative of unauthorized lateral movement.

## Attack Chain

1.  An attacker gains initial access to a system within the network.
2.  The attacker uses WMI to initiate a connection to a remote host on port 135.
3.  The svchost.exe process on the target host accepts an incoming RPC connection from the attacker-controlled system.
4.  WmiPrvSE.exe, the WMI provider host process, spawns a new process based on the attacker's WMI command.
5.  The spawned process executes the attacker's payload or command on the remote host.
6.  The attacker leverages the executed process for further actions, such as data exfiltration or establishing persistence.

## Impact

Successful exploitation and lateral movement via WMI can lead to unauthorized access to sensitive data, compromise of critical systems, and propagation of malware throughout the network. While specific victim counts or sector targeting data are unavailable, the broad applicability of WMI across Windows environments makes this a relevant threat for a wide range of organizations.

## Recommendation

*   Enable Sysmon Event ID 1 (Process Creation) and Event ID 3 (Network Connection) logging to provide necessary data for the rules below.
*   Deploy the Sigma rules provided in this brief to your SIEM to detect suspicious WMI activity and tune them for your environment.
*   Review and create exceptions for known administrative accounts or specific IP addresses used by IT staff to reduce false positives, as mentioned in the overview.
*   Isolate any affected host from the network to prevent further lateral movement if suspicious WMI activity is detected.
*   Monitor network connections with destination port 135 for unusual activity.
