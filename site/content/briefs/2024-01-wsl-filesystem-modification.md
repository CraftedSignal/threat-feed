---
title: Host File System Changes via Windows Subsystem for Linux
slug: 2024-01-wsl-filesystem-modification
description: This rule detects file creation and modification on the host system from the Windows Subsystem for Linux (WSL), potentially indicating defense evasion by adversaries.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - windows
  - wsl
vendors:
  - Elastic
  - Microsoft
  - SentinelOne
products:
  - Elastic Defend
  - SentinelOne Cloud Funnel
  - Windows Subsystem for Linux
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1202
    technique_name: Indirect Command Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/microsoft/WSL
rules:
  - title: WSL Host File System Access via dllhost
    description: Detects file creation and modification on the host system from the Windows Subsystem for Linux using dllhost.exe.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: WSL File Creation Outside User Directories
    description: Detects file creation events outside typical user directories initiated by dllhost.exe related to WSL.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1059.004
    data_sources:
      - file_event
      - windows
rules_count: 2
---

The Windows Subsystem for Linux (WSL) allows users to run a Linux environment directly on Windows. Adversaries may exploit WSL to modify host files stealthily, bypassing traditional security measures and evading detection. This can be achieved by using WSL processes, especially those involving the Plan9FileSystem, to perform file operations on the host system. The detection rule identifies suspicious file operations initiated by `dllhost.exe` with the Plan9FileSystem CLSID "{DFB65C4C-B34F-435D-AFE9-A86218684AA8}" to flag potential defense evasion attempts. This technique can be employed to modify system configurations, plant malicious files, or exfiltrate sensitive data, while blending in with legitimate WSL usage. Elastic has observed this activity and published a detection rule to identify such events.

## Attack Chain

1.  An attacker gains initial access to a Windows system.
2.  WSL is enabled on the target system, if not already enabled.
3.  The attacker executes commands within the WSL environment.
4.  `dllhost.exe` is spawned to facilitate file system operations between WSL and the host.
5.  The attacker uses the Plan9FileSystem to interact with the Windows host file system.
6.  Malicious files are created or existing files are modified on the host system using `dllhost.exe`.
7.  These files may be placed in locations outside of typical user directories to avoid detection.
8.  The attacker achieves their objective, such as data theft or further system compromise, using the modified files or configurations.

## Impact

Successful exploitation can lead to the compromise of sensitive data, modification of critical system files, and the installation of malware on the Windows host. While the exact number of victims and sectors targeted are not specified, this technique allows attackers to bypass traditional security measures, making it difficult to detect malicious activity. The impact could range from data breaches to complete system compromise, depending on the attacker's objectives.

## Recommendation

*   Enable Sysmon process creation and file creation logging to capture the execution of `dllhost.exe` and file modifications (Sysmon Event ID 1 and 11).
*   Deploy the Sigma rule "Host File System Changes via Windows Subsystem for Linux" to your SIEM to detect suspicious file operations involving `dllhost.exe` and the Plan9FileSystem CLSID.
*   Exclude legitimate WSL development directories and processes from the detection rule to reduce false positives.
*   Monitor for processes and file operations involving `dllhost.exe` and the Plan9FileSystem, alerting on unusual activity.
*   Review and whitelist legitimate applications using WSL that may trigger alerts to prevent unnecessary notifications.
