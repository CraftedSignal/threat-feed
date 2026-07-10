---
title: Clearing Windows Console History for Defense Evasion
slug: 2024-01-clearing-console-history
description: Adversaries may clear Windows console history to remove evidence of their activity and evade detection.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - defense-evasion
  - windows
  - console-history
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_clearing_windows_console_history.toml
rules:
  - title: Detect Clearing Console History via CMD
    description: Detects the use of the `cls` command in `cmd.exe` which clears the console screen and history.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Clearing PowerShell History
    description: Detects the use of the `Clear-History` command in PowerShell to clear the command history.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may attempt to remove traces of their commands from a compromised system to hinder forensic analysis and detection efforts. Clearing the console history is one such tactic that reduces the audit trail available to defenders. While not a sophisticated technique, it demonstrates an awareness of system administration practices and a desire to operate covertly. This action can complicate incident response by deleting command-line evidence, making it difficult to reconstruct the attacker's activities. The impact of this behavior is largely dependent on the sophistication of the overall attack and the reliance on console logs for security monitoring.

## Attack Chain

1.  The attacker gains access to a Windows system via an unknown method (e.g., compromised credentials, exploiting a vulnerability).
2.  The attacker opens a command prompt (cmd.exe) or PowerShell console.
3.  The attacker executes commands for reconnaissance, privilege escalation, or lateral movement.
4.  The attacker uses `cls` or `Clear-History` command, or manually edits the console history file.
5.  The console history is cleared, removing a record of previous commands.
6.  The attacker continues malicious activities on the system, now with a reduced audit trail.

## Impact

The primary impact is the reduction of forensic evidence available to security analysts. This can increase the time required to investigate an incident and potentially prevent a full understanding of the attacker's actions. The scope of impact is limited to the specific compromised system where the console history was cleared. This technique is more effective when combined with other evasion tactics, making detection more challenging.
