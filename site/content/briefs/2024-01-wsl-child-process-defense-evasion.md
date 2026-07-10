---
title: Potential Defense Evasion via WSL Child Processes
slug: 2024-01-wsl-child-process-defense-evasion
description: Adversaries may attempt to evade detection by executing malicious commands or scripts through child processes spawned from the Windows Subsystem for Linux (WSL), potentially bypassing traditional Windows-based security monitoring.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - wsl
  - defense-evasion
  - child-process
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_wsl_child_process.toml
rules:
  - title: Detect Suspicious Child Processes Spawned by WSL
    description: Detects suspicious processes being spawned as children of wsl.exe, potentially indicating defense evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - windows
  - title: Detect Network Connections from WSL Child Processes
    description: Detects network connections initiated by processes spawned from WSL, potentially indicating command and control or data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Attackers can leverage the Windows Subsystem for Linux (WSL) to execute commands or scripts that might bypass conventional Windows security measures. This involves spawning child processes from WSL that perform actions otherwise flagged by Windows-based monitoring. While not inherently malicious, the behavior can be abused. Defenders need to monitor child processes spawned by WSL for unusual or suspicious commands and network activity. This technique is particularly relevant as organizations increase their adoption of WSL for development and other legitimate purposes, thus potentially creating blind spots for security tools.

## Attack Chain

1.  The attacker gains initial access to the target system (e.g., via phishing or exploitation).
2.  The attacker enables or utilizes an existing WSL instance.
3.  The attacker executes a shell within the WSL environment (e.g., `wsl.exe`).
4.  From the WSL shell, the attacker executes a script or command designed to evade detection, such as downloading and executing a payload from a remote server using `curl` or `wget`.
5.  This script or command spawns a child process within the WSL environment (e.g., running a Python script using `python evil.py`).
6.  The child process performs malicious actions, such as establishing a reverse shell, exfiltrating data, or modifying system files within the WSL environment, thereby avoiding direct interaction with the Windows OS.
7.  The attacker leverages the WSL environment as a proxy to communicate with external C2 servers, further obfuscating their activity.

## Impact

Successful exploitation allows attackers to execute commands, download malicious payloads, and potentially establish persistence without triggering Windows-specific security alerts. This can lead to data exfiltration, lateral movement within the network, and ultimately, compromise of sensitive systems. The impact is increased if the organization relies heavily on Windows-centric security solutions without adequate monitoring of WSL activity.
