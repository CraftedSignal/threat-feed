---
title: Suspicious Windows PowerShell Arguments Detected
slug: 2024-09-susp-powershell-args
description: This rule identifies the execution of PowerShell with suspicious argument values, often observed during malware installation, by detecting unusual PowerShell arguments indicative of abuse, focusing on patterns like encoded commands, suspicious downloads, and obfuscation techniques.
date: "2026-05-04T14:17:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - powershell
  - malware
  - execution
vendors:
  - Elastic
  - Microsoft
  - Crowdstrike
  - SentinelOne
products:
  - Elastic Defend
  - Microsoft Defender XDR
  - Sysmon
  - Crowdstrike
  - SentinelOne Cloud Funnel
  - Elastic Endgame
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1140
    technique_name: Deobfuscate/Decode Files or Information
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/execution_windows_powershell_susp_args.toml
rules:
  - title: Detect PowerShell with Encoded Command Arguments
    description: Detects PowerShell processes using encoded command arguments, a common technique for obfuscating malicious scripts.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1027
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect PowerShell Downloading Files from the Internet
    description: Detects PowerShell processes using WebClient or Invoke-WebRequest to download files from the internet, which may indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.001
      - T1105
    data_sources:
      - process_creation
      - windows
  - title: Detect PowerShell Command Obfuscation via String Manipulation
    description: Detects PowerShell using string manipulation and concatenation to obfuscate commands
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1027.010
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This detection rule identifies the execution of PowerShell with suspicious argument values on Windows systems. This behavior is frequently associated with malware installation and other malicious activities. PowerShell is a powerful scripting language, and adversaries often exploit its capabilities to execute malicious scripts, download payloads, and obfuscate commands. The rule focuses on detecting patterns such as encoded commands, suspicious downloads (e.g., using WebClient or Invoke-WebRequest), and various obfuscation techniques used to evade detection. The rule is designed to work with various data sources, including Elastic Defend, Windows Security Event Logs, Sysmon, and third-party EDR solutions like CrowdStrike, Microsoft Defender XDR, and SentinelOne, enhancing its applicability across different environments.

## Attack Chain

1.  An attacker gains initial access to a Windows system (e.g., through phishing or exploiting a vulnerability).
2.  The attacker uses PowerShell to download a malicious payload from a remote server using commands like `DownloadFile` or `DownloadString`.
3.  The downloaded payload is often encoded or obfuscated to evade detection. Common techniques include Base64 encoding, character manipulation, and compression.
4.  PowerShell is then used to decode or deobfuscate the payload using methods like `[Convert]::FromBase64String` or `[char[]](...) -join ''`.
5.  The deobfuscated payload is executed directly in memory using techniques like `iex` (Invoke-Expression) or `Reflection.Assembly.Load`.
6.  The executed payload performs malicious actions, such as installing malware, establishing persistence, or exfiltrating data.
7.  The attacker may use techniques like `WebClient` to download files from a remote URL.
8.  Commands like `nslookup -q=txt` are used for command and control.

## Impact

Successful exploitation can lead to malware installation, data theft, system compromise, and further propagation of the attack within the network. The detection of suspicious PowerShell arguments helps to identify and prevent these malicious activities before significant damage can occur. Without proper detection, attackers can maintain persistence, escalate privileges, and compromise sensitive data. The rule helps defenders identify and respond to these threats quickly, minimizing the impact of potential attacks.

## Recommendation

*   Deploy the Sigma rules provided in this brief to your SIEM to detect suspicious PowerShell activity.
*   Enable Sysmon process creation logging with command line arguments to ensure the necessary data is captured for the Sigma rules to function effectively.
*   Investigate any alerts generated by the Sigma rules to determine the legitimacy of the PowerShell activity and take appropriate remediation steps.
*   Continuously tune the Sigma rules based on your environment to reduce false positives and improve detection accuracy.
