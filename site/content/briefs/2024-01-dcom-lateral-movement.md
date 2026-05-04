---
title: DCOM Lateral Movement via ShellWindows/ShellBrowserWindow
slug: 2024-01-dcom-lateral-movement
description: This analytic identifies the use of Distributed Component Object Model (DCOM) to execute commands on a remote host, specifically when launched via ShellBrowserWindow or ShellWindows Application COM objects, indicating potential lateral movement by an attacker.
date: "2024-01-04T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lateral-movement
  - dcom
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1559
    technique_name: Inter-Process Communication
references:
  - https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/
rules:
  - title: DCOM Lateral Movement with Explorer.exe
    description: Detects DCOM lateral movement by identifying explorer.exe spawning suspicious child processes after an incoming network connection on high ports.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.003
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Explorer.exe Child Processes
    description: Detects suspicious child processes of explorer.exe which may indicate lateral movement via DCOM
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies the abuse of Distributed Component Object Model (DCOM) for lateral movement within a Windows environment. DCOM allows software components to communicate across a network, and attackers may leverage it to execute commands remotely. This rule specifically focuses on the use of ShellBrowserWindow or ShellWindows Application COM objects as the launching point for these remote commands. The technique enables stealthy lateral movement, as it leverages legitimate Windows functionality. This activity is detected by identifying incoming TCP connections on high ports associated with `explorer.exe` spawning child processes, which are indicative of DCOM abuse. The rule is designed to detect this behavior and alert security teams to potential unauthorized lateral movement attempts.

## Attack Chain

1. An attacker gains initial access to a compromised host within the network.
2. The attacker uses DCOM to initiate a connection to a target host.
3. The DCOM connection is established to the target host via high TCP ports (above 49151).
4. The `explorer.exe` process on the target host receives the DCOM connection.
5. The attacker uses ShellBrowserWindow or ShellWindows COM objects to execute commands.
6. `explorer.exe` spawns a child process to execute the attacker-supplied command.
7. The spawned process performs malicious actions, such as reconnaissance or further lateral movement.

## Impact

Successful exploitation allows attackers to execute arbitrary commands on the target system, leading to potential data exfiltration, system compromise, and further lateral movement within the network. This can result in significant damage, including data breaches, financial losses, and reputational harm. The DCOM protocol is commonly used in many Windows environments, so this technique could be broadly applicable across many victim organizations.

## Recommendation

*   Deploy the Sigma rule "DCOM Lateral Movement with Explorer.exe" to your SIEM and tune for your environment to detect suspicious process creations spawned by explorer.exe.
*   Enable Sysmon Event ID 3 (Network Connection) and Event ID 1 (Process Creation) logging to ensure the required data is available for the Sigma rule to function correctly.
*   Review network activity for incoming TCP connections to high ports (49151+) associated with `explorer.exe`, as highlighted in the "Incoming DCOM Lateral Movement with ShellBrowserWindow or ShellWindows" detection.
*   Investigate any unusual or unexpected child processes spawned by `explorer.exe`, as detected by the Sigma rule.
