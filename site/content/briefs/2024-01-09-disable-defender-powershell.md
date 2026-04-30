---
title: Disabling Windows Defender Security Settings via PowerShell
slug: 2024-01-09-disable-defender-powershell
description: Attackers use PowerShell commands, including base64-encoded variants, to disable or weaken Windows Defender settings, impairing defenses on compromised systems.
date: "2024-01-09T10:00:00Z"
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
affected_os:
  - Windows
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
  - title: Detect Suspicious PowerShell Defender Disable
    description: Detects PowerShell commands used to disable Windows Defender features
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.001
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious PowerShell Encoded Commands
    description: Detects base64-encoded PowerShell commands used to disable Windows Defender
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.001
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers commonly attempt to disable or weaken Windows Defender to evade detection and facilitate malicious activities. This involves using PowerShell commands like `Set-MpPreference` or `Add-MpPreference` to modify Defender's configuration. Adversaries may also utilize base64 encoding to obfuscate these commands, bypassing simple command-line inspection. This activity typically occurs post-compromise, as part of a broader attack chain, and allows for the deployment of malware or other malicious tools without interference from the built-in antivirus. Detection of these techniques is crucial for maintaining the integrity of the system and preventing further damage. The scope of this threat includes any Windows environment where PowerShell is enabled and Windows Defender is used as the primary antivirus solution.

## Attack Chain

1. Initial access is achieved through an existing compromise (e.g., phishing, exploit).
2. The attacker gains a foothold on the system and escalates privileges if necessary.
3. PowerShell is launched, either directly or through a parent process like `cmd.exe`.
4. The attacker uses `Set-MpPreference` or `Add-MpPreference` with parameters like `-DisableRealtimeMonitoring`, `-DisableIOAVProtection`, `-DisableBehaviorMonitoring`, or `-DisableBlockAtFirstSeen` to weaken Defender.
5. Alternatively, the attacker crafts a base64-encoded PowerShell command that performs the same actions.
6. The encoded command is executed using the `-EncodedCommand` or `-enc` parameter.
7. Windows Defender's security settings are modified, reducing its effectiveness.
8. The attacker proceeds with deploying malware, exfiltrating data, or other malicious objectives.

## Impact

Successful execution of these commands results in a weakened or disabled Windows Defender, leaving the system vulnerable to malware infections and other threats. This can lead to data breaches, system compromise, and financial loss. The impact is especially significant in environments where Windows Defender is the primary security solution. While the number of victims is unknown, the technique is widely applicable across Windows environments.

## Recommendation

*   Monitor process creation events for PowerShell executions (`powershell.exe`, `pwsh.exe`) with command-line arguments related to disabling Windows Defender using the Sigma rule "Detect Suspicious PowerShell Encoded Commands".
*   Enable PowerShell script block logging to capture the full content of executed scripts, which can reveal base64-encoded commands (reference: references - https://docs.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2019-ps).
*   Deploy the Sigma rule "Disabling Windows Defender Security Settings via PowerShell" to your SIEM and tune for your environment.
*   Investigate any instances of `Set-MpPreference` or `Add-MpPreference` commands with arguments disabling real-time monitoring, IOAV protection, behavior monitoring, or block-at-first-seen features.
