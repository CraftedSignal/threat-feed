---
title: Disabling Windows Defender Security Settings via PowerShell
slug: 2024-01-09-disable-defender-powershell
description: Attackers use PowerShell commands, including base64-encoded variants, to disable or weaken Windows Defender settings, impairing defenses on compromised systems.
date: "2024-01-09T10:00:00Z"
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

Attackers commonly attempt to disable or weaken Windows Defender to evade detection and facilitate malicious activities. This involves using PowerShell commands like `Set-MpPreference` or `Add-MpPreference` to modify Defender's configuration. Adversaries may also utilize base64 encoding to obfuscate these commands, bypassing simple command-line inspection. This activity typically occurs post-compromise, as part of a broader attack chain, and allows for the deployment of malware or other…
