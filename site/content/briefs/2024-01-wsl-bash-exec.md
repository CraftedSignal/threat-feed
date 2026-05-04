---
title: Suspicious Execution via Windows Subsystem for Linux
slug: 2024-01-wsl-bash-exec
description: Adversaries may leverage the Windows Subsystem for Linux (WSL) to execute malicious Linux commands, bypassing traditional Windows security measures, detected by monitoring process execution and command-line arguments.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - defense-evasion
  - execution
  - credential-access
  - windows
vendors:
  - Elastic
  - Microsoft
  - SentinelOne
products:
  - Elastic Defend
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
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
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://blog.f-secure.com/hunting-for-windows-subsystem-for-linux/
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Wsl/
  - https://blog.qualys.com/vulnerabilities-threat-research/2022/03/22/implications-of-windows-subsystem-for-linux-for-adversaries-defenders-part-1
rules:
  - title: Detect Suspicious WSL Activity
    description: Detects suspicious command line arguments used with wsl.exe that may indicate malicious activity within the Windows Subsystem for Linux.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - defense_evasion
      - execution
    techniques:
      - T1003
      - T1059.004
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect Bash Execution from WSL
    description: Detects execution of bash.exe with command line arguments indicating malicious use within the Windows Subsystem for Linux.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.004
      - T1202
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Windows Subsystem for Linux (WSL) enables users to run Linux binaries natively on Windows, creating an opportunity for adversaries to evade detection by executing malicious Linux commands without triggering traditional Windows security alerts. This technique involves leveraging WSL's bash shell to perform actions that might otherwise be flagged if executed directly within the Windows environment. This alert focuses on detecting suspicious behaviors indicative of malicious use of WSL, such as unauthorized access to sensitive files, use of network tools, or unusual command-line arguments. This can be used to facilitate lateral movement, data exfiltration, or other malicious activities. The Qualys blog post "Implications of Windows Subsystem for Linux for Adversaries & Defenders" (2022-03-22) describes this attack vector in detail.

## Attack Chain

1. An attacker gains initial access to a Windows system.
2. The attacker enables WSL if it is not already enabled.
3. The attacker executes `wsl.exe` to start a Linux environment.
4. Inside the WSL environment, the attacker uses `bash` to execute malicious commands.
5. The attacker attempts to access sensitive files such as `/etc/shadow` or `/etc/passwd` to gather credentials.
6. The attacker uses network tools like `curl` to download or upload malicious payloads.
7. The attacker executes scripts to establish persistence within the WSL environment.
8. The attacker uses the compromised WSL environment to move laterally to other systems or exfiltrate data.

## Impact

Successful exploitation via WSL can lead to a variety of negative outcomes, including unauthorized access to sensitive information, credential compromise, and lateral movement within the network. While specific victim counts are unavailable, this technique can significantly increase the attack surface and reduce the effectiveness of traditional Windows-based security measures, affecting organizations across various sectors.

## Recommendation

*   Enable Sysmon process creation logging to capture `wsl.exe` and `bash.exe` executions (reference: Sysmon Event ID 1 setup in rule setup section).
*   Deploy the Sigma rule "Detect Suspicious WSL Activity" to your SIEM and tune for your environment.
*   Monitor process command lines for suspicious arguments used with `wsl.exe`, such as access to `/etc/shadow` or `/etc/passwd` (reference: Sigma rule selection criteria).
*   Investigate and whitelist legitimate uses of WSL within your environment to reduce false positives (reference: False positive analysis in the rule description).
