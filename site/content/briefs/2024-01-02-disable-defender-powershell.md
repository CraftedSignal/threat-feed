---
title: Disabling Windows Defender Security Settings via PowerShell
slug: 2024-01-02-disable-defender-powershell
description: Attackers use PowerShell commands like Set-MpPreference or Add-MpPreference, often with base64 encoding, to disable or weaken Windows Defender security settings in order to evade detection and execute malicious payloads.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - powershell
  - windows
vendors:
  - Microsoft
products:
  - Windows Defender
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2019-ps
  - https://www.elastic.co/security-labs/operation-bleeding-bear
  - https://www.elastic.co/security-labs/invisible-miners-unveiling-ghostengine
  - https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_defender_disable_feature.yml
rules:
  - title: Detect Windows Defender Disabling via Set-MpPreference
    description: Detects attempts to disable Windows Defender features using the Set-MpPreference PowerShell command.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Windows Defender Disabling via Base64 Encoded PowerShell
    description: Detects attempts to disable Windows Defender features using Base64 encoded PowerShell commands.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Add-MpPreference Use for Defender Exclusions
    description: Detects the use of Add-MpPreference to add exclusions to Windows Defender, which could be used to bypass detection.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Attackers frequently attempt to disable or weaken Windows Defender to facilitate the execution of malware and other malicious activities. This is often achieved through the use of PowerShell commands like `Set-MpPreference` and `Add-MpPreference`, which can modify various Defender settings. To evade detection, adversaries may encode these commands using Base64, making it more difficult for traditional command-line inspection techniques to identify the malicious intent. This activity is a common tactic in post-exploitation scenarios, allowing attackers to operate with reduced risk of being detected by the built-in antivirus solution. Detection of this behavior is critical for identifying and responding to potential intrusions. The Elastic detection rule aims to catch both standard and encoded PowerShell commands used for this purpose.

## Attack Chain

1. An attacker gains initial access to a Windows system through methods such as phishing or exploiting a vulnerability.
2. The attacker elevates privileges to gain necessary permissions to modify Windows Defender settings.
3. The attacker uses the `powershell.exe` process to execute commands.
4. The attacker uses `Set-MpPreference` or `Add-MpPreference` to disable real-time monitoring.
5. The attacker may use Base64 encoding (e.g., using the `-EncodedCommand` parameter) to obfuscate the PowerShell commands.
6. The encoded command is executed, modifying Windows Defender settings.
7. Windows Defender's real-time monitoring is disabled, allowing the attacker to execute malicious payloads without immediate detection.
8. The attacker proceeds with their objectives, such as deploying ransomware or exfiltrating data.

## Impact

Successful disabling of Windows Defender can lead to a significant increase in the risk of malware infection and data breach. With real-time protection disabled, the system becomes vulnerable to various threats, including ransomware, Trojans, and other malicious software. This can result in data loss, system compromise, and potential financial damages. The impact can be severe, especially if the compromised system handles sensitive information or is critical to business operations.

## Recommendation

*   Deploy the Sigma rule "Disabling Windows Defender Security Settings via PowerShell" to your SIEM and tune for your environment.
*   Enable PowerShell Script Block Logging to gain better visibility into the commands being executed (referenced in Sysmon setup instructions).
*   Monitor process creation events for PowerShell processes executing commands with `-EncodedCommand` or containing specific Base64 encoded strings to detect obfuscated attempts to disable Windows Defender.
*   Investigate any instances of `Set-MpPreference` or `Add-MpPreference` being used, especially if accompanied by unusual parent processes or command-line arguments.
