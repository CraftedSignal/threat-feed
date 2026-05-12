---
title: Incoming DCOM Lateral Movement with MMC
slug: 2026-05-incoming-dcom-lateral-movement
description: Detection of Distributed Component Object Model (DCOM) abuse to execute commands remotely via the MMC20 Application COM object, potentially indicating lateral movement.
date: "2026-05-12T17:46:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - lateral-movement
  - dcom
  - windows
vendors:
  - Elastic
  - Microsoft
products:
  - Elastic Defend
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
references:
  - https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/lateral_movement_dcom_mmc20.toml
rules:
  - title: Detect Incoming DCOM Lateral Movement with MMC Child Process
    description: Detects DCOM lateral movement attempts by identifying incoming network connections to mmc.exe followed by the creation of a child process.
    platform: sigma
    severity: high
    tactics:
      - lateral_movement
    techniques:
      - T1021
    data_sources:
      - process_creation
      - windows
  - title: Detect Incoming DCOM Network Connection to MMC
    description: Detects DCOM lateral movement attempts by identifying incoming network connections to mmc.exe on high ports.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

This rule identifies the use of Distributed Component Object Model (DCOM) for remote command execution, specifically leveraging the MMC20 Application COM object. Attackers may abuse DCOM applications to move laterally within a network. The detection focuses on incoming network connections to Windows hosts where `mmc.exe` is running and subsequently spawns child processes. This technique, known since at least 2017, can bypass traditional security controls and provides a stealthy way to execute commands on remote systems. The Elastic rule ID for this behavior is 51ce96fb-9e52-4dad-b0ba-99b54440fc9a, last updated on 2026/05/03.

## Attack Chain

1. An attacker compromises a system and seeks to move laterally.
2. The attacker uses DCOM to initiate a connection to a remote Windows host. The connection targets `mmc.exe` via high ports (>= 49152) using TCP.
3. The target `mmc.exe` receives the incoming DCOM connection.
4. The MMC20 Application COM object is used to execute a command.
5. `mmc.exe` spawns a child process to execute the command. This child process could be cmd.exe, PowerShell, or another executable.
6. The child process performs malicious actions, such as reconnaissance, privilege escalation, or data exfiltration.
7. The attacker may establish persistence or move to other systems in the network.

## Impact

Successful exploitation allows attackers to execute arbitrary commands on remote systems, potentially leading to data theft, system compromise, and further lateral movement. This can affect all Windows systems within an organization if DCOM is not properly secured. The impact can range from minor data breaches to complete network compromise, depending on the attacker's objectives and the privileges of the compromised accounts.

## Recommendation

*   Enable Sysmon process creation and network connection logging to capture the necessary events (Sysmon Event ID 1 and 3) to trigger the rules below.
*   Deploy the Sigma rules below to your SIEM and tune for your environment.
*   Restrict DCOM/RPC between workstations to prevent unauthorized lateral movement.
*   Monitor network connections to `mmc.exe` processes, especially those originating from unusual source IPs or ports.
*   Review and restrict Microsoft Management Console inbound access to only authorized administrators and systems.
