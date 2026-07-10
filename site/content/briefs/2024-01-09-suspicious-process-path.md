---
title: Windows Suspicious Process Execution from Unusual File Paths
slug: 2024-01-09-suspicious-process-path
description: Adversaries may execute malicious processes from unusual file paths (e.g., within Windows, Users, or Recycle Bin directories) to evade defenses and potentially compromise systems.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - suspicious-process
  - defense-evasion
  - persistence
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://www.trendmicro.com/vinfo/hk/threat-encyclopedia/malware/trojan.ps1.powtran.a/
  - https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/
  - https://twitter.com/pr0xylife/status/1590394227758104576
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.asyncrat
  - https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/
rules:
  - title: Suspicious Process Executed from Recycle Bin
    description: Detects processes running directly from the Recycle Bin, which is highly unusual and often indicative of malicious activity.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1036.005
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Process Executed from Windows Fonts Directory
    description: Detects processes running directly from the Windows Fonts directory, which is an unexpected location for executable files.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1036.005
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Process Executed from Public User Directory
    description: Detects processes running directly from the Public user directory, often used for initial payload storage.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036.005
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This threat brief focuses on the execution of processes from suspicious or unusual file paths on Windows systems, a common tactic used by adversaries to bypass security controls and execute malicious code. Attackers often place malware in directories like `C:\Windows\Fonts`, `C:\Users\Public`, or the Recycle Bin, as these locations are less likely to be closely monitored. This technique allows for the execution of unauthorized software, potentially leading to system compromise, data exfiltration, or further malicious activities within the environment. The referenced reports detail instances where malware like AsyncRAT, various stealers, and ransomware variants were deployed using such methods. Defenders should prioritize monitoring process execution from atypical locations to detect and prevent such attacks.

## Attack Chain

1.  Initial Access: The attacker gains initial access through an unknown vector (e.g., drive-by download, exploiting a vulnerability, or social engineering).
2.  Payload Delivery: A malicious executable or script (e.g., a PowerShell script) is deposited in a suspicious directory such as `C:\Users\Public\` or `C:\Windows\Temp\`.
3.  Persistence (Optional): The attacker establishes persistence by creating a scheduled task or modifying a registry key to execute the payload upon system startup or user logon.
4.  Execution: The malicious executable or script is executed using a legitimate Windows process such as `cmd.exe` or `powershell.exe`, or directly by the user.
5.  Defense Evasion: The attacker employs techniques to evade detection, such as obfuscation, process injection, or running the malicious code from a trusted directory.
6.  Command and Control: The executed malware establishes a connection to a remote command-and-control (C2) server to receive further instructions.
7.  Lateral Movement (Optional): The attacker attempts to move laterally to other systems within the network by exploiting vulnerabilities or using stolen credentials.
8.  Impact: The attacker achieves their objective, such as data exfiltration, ransomware deployment, or disruption of services.

## Impact

Successful exploitation can lead to significant damage, including data theft, system compromise, and ransomware infections. While the exact number of victims is unknown, this technique has been observed in various campaigns involving malware such as stealers, remote access trojans (RATs) like AsyncRAT, and ransomware. Industries that are commonly targeted by these types of attacks include healthcare, finance, and critical infrastructure. The impact could range from financial losses and reputational damage to disruption of essential services.

## Recommendation

*   Enable Sysmon process-creation logging to capture detailed information about process executions, including file paths (Sysmon EventID 1).
*   Deploy the Sigma rule "Suspicious Process Executed from Recycle Bin" to detect processes running directly from the Recycle Bin directory (logsource: process_creation).
*   Deploy the Sigma rule "Suspicious Process Executed from Windows Fonts Directory" to detect processes running directly from the Windows Fonts directory (logsource: process_creation).
*   Investigate any alerts generated by these rules, focusing on processes with unusual parent-child relationships or command-line arguments.
