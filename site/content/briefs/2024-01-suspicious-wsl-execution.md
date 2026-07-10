---
title: Suspicious Execution via Windows Subsystem for Linux
slug: 2024-01-suspicious-wsl-execution
description: This rule detects suspicious execution via the Windows Subsystem for Linux (WSL), which adversaries may leverage to execute Linux commands and bypass traditional Windows security measures.
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - wsl
  - windows-subsystem-for-linux
  - defense-evasion
vendors:
  - Microsoft
products:
  - Windows Subsystem for Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1202
    technique_name: Indirect Command Execution
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://blog.f-secure.com/hunting-for-windows-subsystem-for-linux/
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Wsl/
  - https://blog.qualys.com/vulnerabilities-threat-research/2022/03/22/implications-of-windows-subsystem-for-linux-for-adversaries-defenders-part-1
rules:
  - title: Suspicious WSL Bash Execution
    description: Detects suspicious execution of bash within the Windows Subsystem for Linux.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - defense_evasion
      - execution
    techniques:
      - T1003.008
      - T1059.004
    data_sources:
      - process_creation
      - windows
  - title: WSL Executing Suspicious Network Commands
    description: Detects WSL executing curl, wget or other network commands
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.004
      - T1071.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Windows Subsystem for Linux (WSL) allows users to run Linux binaries natively on Windows. Adversaries may abuse WSL to execute commands stealthily, bypassing Windows security measures. This rule detects suspicious WSL activity by monitoring specific executable paths (e.g., `bash.exe`), command-line arguments, and parent-child process relationships. The detection logic focuses on deviations from typical WSL usage patterns to uncover potential threats. This includes detecting `bash.exe` execution with atypical command-line arguments, WSL processes accessing sensitive files like `/etc/shadow` or `/etc/passwd`, and unexpected parent-child process relationships involving `wsl.exe`. This activity can be used for initial access, defense evasion, and credential access.

## Attack Chain

1.  The attacker enables WSL on a compromised Windows host if it is not already enabled.
2.  The attacker executes `wsl.exe` to start a Linux environment.
3.  The attacker uses `wsl.exe` to execute `bash.exe` with suspicious command-line arguments, such as those used to access sensitive files or download malicious payloads.
4.  The attacker leverages `bash.exe` to download and execute further payloads from the internet using tools like `curl` or `wget`.
5.  The attacker attempts to access sensitive files like `/etc/shadow` or `/etc/passwd` within the WSL environment for credential dumping (T1003.008).
6.  The attacker uses the WSL environment as a staging ground to perform lateral movement within the network.
7.  The attacker leverages indirect command execution (T1202) to execute malicious commands on the windows host from the WSL instance.
8.  The attacker uses the compromised host to achieve their final objective, such as data exfiltration or deploying ransomware.

## Impact

Successful exploitation via WSL can lead to the compromise of Windows systems, credential theft, and further malicious activities. If an attacker successfully leverages WSL, they can bypass traditional Windows security measures, potentially leading to data breaches, system compromise, and lateral movement within the network. WSL abuse can affect any Windows system where WSL is enabled, including developer workstations and servers.

## Recommendation

*   Enable Sysmon process creation logging to detect suspicious `bash.exe` and `wsl.exe` executions, as described in the rule's logsource.
*   Deploy the Sigma rule "Suspicious Execution via Windows Subsystem for Linux" to your SIEM and tune for your environment.
*   Monitor process command lines for access to sensitive files (e.g., `/etc/shadow`, `/etc/passwd`) within the WSL environment, as referenced in the Attack Chain and rule logic.
*   Implement network monitoring to detect unusual outbound connections from WSL processes, as this can indicate payload downloads or command and control activity.
*   Review WSL configurations on systems to identify any unauthorized changes or installations, as described in the investigation guide.
