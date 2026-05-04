---
title: Suspicious PowerShell Execution via Windows Script Host
slug: 2024-01-script-powershell-execution
description: Detection of PowerShell processes launched by cscript.exe or wscript.exe, indicative of potential malicious initial access or execution attempts.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - initial-access
  - execution
  - windows
  - powershell
  - script
vendors:
  - Microsoft
  - Elastic
  - SentinelOne
products:
  - Microsoft Defender XDR
  - Elastic Defend
  - SentinelOne Cloud Funnel
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.elastic.co/security-labs/operation-bleeding-bear
  - https://attack.mitre.org/techniques/T1566/
  - https://attack.mitre.org/techniques/T1566/001/
  - https://attack.mitre.org/techniques/T1059/
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1059/005/
  - https://attack.mitre.org/techniques/T1059/007/
rules:
  - title: Windows Script Host Spawning PowerShell
    description: Detects PowerShell processes launched by cscript.exe or wscript.exe, which may indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.001
      - T1566
    data_sources:
      - process_creation
      - windows
  - title: Suspicious WScript with Encoded PowerShell Command
    description: Detects wscript.exe launching with command lines containing encoded PowerShell commands
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.001
      - T1059.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies PowerShell execution initiated by Windows Script Host processes (cscript.exe or wscript.exe). Attackers often use Windows Script Host (WSH) to execute malicious scripts as an initial access method. These scripts can act as droppers for second-stage payloads or download tools and utilities necessary for further compromise. The rule focuses on the parent-child process relationship between WSH and PowerShell, highlighting a common technique used to bypass security controls and execute arbitrary commands on a compromised system. This activity is relevant to defenders as it represents a potential entry point for various attacks, including malware deployment and data exfiltration. The detection logic is based on process execution events observed in Windows environments and is designed to work with data from Elastic Defend, Microsoft Defender XDR, SentinelOne Cloud Funnel, and Sysmon.

## Attack Chain

1.  The user receives a phishing email with a malicious attachment (e.g., a .vbs or .js file).
2.  The user opens the attachment, which is processed by either wscript.exe or cscript.exe.
3.  The scripting engine executes the embedded malicious code.
4.  The script downloads a PowerShell script from a remote server or contains an embedded, obfuscated PowerShell command.
5.  The script uses wscript.exe or cscript.exe to launch powershell.exe to execute the downloaded or embedded PowerShell script.
6.  PowerShell executes, performing malicious actions such as downloading additional payloads, modifying system settings, or establishing persistence.
7.  PowerShell attempts to connect to external command-and-control servers to receive further instructions.
8.  The attacker gains initial access to the system and can proceed with lateral movement, data exfiltration, or other malicious activities.

## Impact

Successful exploitation can lead to initial access, allowing attackers to deploy malware, steal sensitive information, or perform other malicious activities. The impact can range from data breaches and financial losses to reputational damage. The severity depends on the attacker's objectives and the level of access they gain. The number of affected systems depends on the scope of the phishing campaign or other initial access methods used to deliver the malicious script.

## Recommendation

*   Enable Sysmon process creation logging to capture the necessary event data for the rules below.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
*   Investigate process execution chains where cscript.exe or wscript.exe spawn powershell.exe using the provided Sigma rules.
*   Implement email security measures to block phishing emails with script attachments.
*   Monitor network connections originating from PowerShell processes for suspicious outbound traffic.
