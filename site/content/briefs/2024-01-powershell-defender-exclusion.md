---
title: PowerShell Windows Defender Exclusion Commands
slug: 2024-01-powershell-defender-exclusion
description: Attackers use PowerShell commands with `Add-MpPreference` or `Set-MpPreference` to create Windows Defender exclusions, allowing malware to execute undetected.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - powershell
  - windows-defender
  - exclusion
  - defense-evasion
vendors:
  - Microsoft
products:
  - Windows Defender
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://tccontre.blogspot.com/2020/01/remcos-rat-evading-windows-defender-av.html
  - https://app.any.run/tasks/cf1245de-06a7-4366-8209-8e3006f2bfe5/
  - https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/
rules:
  - title: PowerShell Add-MpPreference Exclusion
    description: Detects the use of Add-MpPreference to create Windows Defender exclusions via PowerShell.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - powershell
      - windows
  - title: PowerShell Set-MpPreference Exclusion
    description: Detects the use of Set-MpPreference to modify Windows Defender exclusions via PowerShell.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - powershell
      - windows
rules_count: 2
---

This brief addresses the threat of attackers using PowerShell to manipulate Windows Defender exclusions. The technique involves executing commands like `Add-MpPreference` or `Set-MpPreference` with specific exclusion parameters. By successfully creating these exclusions, attackers can prevent Windows Defender from scanning or detecting malicious files, folders, or processes. This is significant because it allows malware to operate unimpeded, enabling various malicious activities such as data theft, lateral movement, and persistence. Several threat actors and malware families, including Remcos RAT, AgentTesla, WhisperGate, Warzone RAT, NetSupport RMM tool abuse, and BlankGrabber Stealer, have been observed using these techniques. The attacks often target endpoints running Windows operating systems. This poses a high risk to organizations relying on Windows Defender as a primary security control.

## Attack Chain

1.  **Initial Access:** The attacker gains initial access to the system through various means, such as exploiting vulnerabilities or compromising credentials. (T1190, T1133)
2.  **Privilege Escalation:** If necessary, the attacker escalates privileges to gain the required permissions to modify Windows Defender settings. (T1068)
3.  **PowerShell Execution:** The attacker executes a PowerShell script or command directly in the PowerShell console. (T1059.001)
4.  **Detection Evasion:** The attacker tests the command in a sandbox environment to ensure it does not trigger existing detections and modify as needed.
5.  **Add-MpPreference or Set-MpPreference:** The attacker uses `Add-MpPreference` or `Set-MpPreference` to create a new exclusion. The command specifies the path, file, or process to be excluded from Windows Defender scans.
6.  **Persistence:** The attacker may establish persistence by scheduling tasks or modifying registry keys to ensure the exclusion remains active after a reboot. (T1053.005, T1547.001)
7.  **Malware Deployment:** With Windows Defender effectively blinded, the attacker deploys malware, such as a Remote Access Trojan (RAT) or information stealer, onto the system.
8.  **Data Exfiltration/Lateral Movement:** The malware executes its primary function, such as stealing sensitive data or moving laterally to other systems on the network. (TA0010, TA0008)

## Impact

Successful exploitation allows attackers to bypass Windows Defender, leading to undetected malware execution. This can result in data breaches, financial losses, reputational damage, and disruption of business operations. The impact can range from individual workstation compromises to widespread network infections depending on the attacker's objectives. CISA has highlighted this technique in relation to several malware campaigns like WhisperGate affecting Ukrainian organizations.

## Recommendation

*   Deploy the Sigma rules provided to detect PowerShell commands creating Windows Defender exclusions within your environment. Tune the rules as needed for your specific environment.
*   Enable PowerShell Script Block Logging (EventCode 4104) to provide the necessary data source for the provided Sigma rules.
*   Review and audit existing Windows Defender exclusions to identify any suspicious or unauthorized entries.
*   Monitor PowerShell command-line activity for the use of `Add-MpPreference` and `Set-MpPreference` commands with exclusion-related parameters.
