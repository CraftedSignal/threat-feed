---
title: PowerShell Dynamic Module Invocation via ExportedCommands Array Indexing
slug: 2026-10-powershell-dynamic-invocation
description: Adversaries are utilizing PowerShell module enumeration and array-based indexing of exported commands to dynamically invoke cmdlets and bypass string-based security detections.
date: "2026-10-06T13:10:28Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - obfuscation
  - defense-evasion
  - powershell
  - execution
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The technique uses PowerShell script blocks to dynamically invoke cmdlets via array indices to evade detection.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: This can be used to evade detections that look for explicit strings such as Invoke-RestMethod or Invoke-Expression.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_cmdlet_invocation_via_exported_commands_array_index.yml
  - https://www.linkedin.com/posts/mark-o-halloran1_clickfix-defense-evasion-tactic-today-i-ugcPost-7453463467736408064-snrp/
rules:
  - title: Detect PowerShell Dynamic Module Invocation via ExportedCommands Array Index
    description: Detects obfuscated PowerShell scripts that enumerate Microsoft.PowerShell.Utility exported commands and invoke cmdlets indirectly by array index.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - stealth
    techniques:
      - T1027
      - T1059.001
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all Windows endpoints.
      owner: IT Operations
      due: 72h
      evidence: Required for visibility into script block content.
    - action: Deploy the Sigma rule to the SIEM to detect dynamic command invocation.
      owner: Detection Engineering
      due: 48h
      evidence: Provides detection capability for obfuscated PowerShell commands.
  hunt_leads:
    - lead: Search ScriptBlockText for patterns involving 'Get-Module' followed by 'ExportedCommands' and array index access like [*].
      technique_id: T1059.001
      data_needed:
        - Event ID 4104
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source explicitly identifies these patterns as indicative of the obfuscated invocation technique.
---

This threat involves the use of obfuscation techniques within PowerShell scripts to bypass security controls. By enumerating commands exported by modules, specifically the 'Microsoft.PowerShell.Utility' module, an attacker can access cmdlets through their index in the 'ExportedCommands' array rather than invoking them directly by name. This technique allows attackers to execute powerful tools such as 'Invoke-Expression' or 'Invoke-RestMethod' without including these suspicious strings in their scripts, effectively evading static detection methods that monitor for command names. This method of dynamic invocation is a form of obfuscation that hides the intent and actions of the script during execution, making it more difficult for defenders to monitor script block contents effectively.

## Impact

Successful exploitation of this obfuscation technique allows adversaries to execute malicious payloads, perform network communication, or carry out lateral movement while remaining hidden from signature-based monitoring. It significantly degrades the efficacy of security tools relying on static analysis of script block content, potentially allowing an attacker to persist or maintain command-and-control communication undetected for longer periods.

## Recommendation

Deploy the provided Sigma rule to your SIEM to monitor for script blocks that enumerate PowerShell module exports combined with array-based indexing, and tune for known legitimate administrative scripts that may utilize this rare pattern. Enable PowerShell Script Block Logging (Event ID 4104) across all endpoints to ensure the necessary telemetry is available for this detection.
