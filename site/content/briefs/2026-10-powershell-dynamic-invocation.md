---
title: PowerShell Dynamic Module Invocation via ExportedCommands Array Indexing
slug: 2026-10-powershell-dynamic-invocation
description: Attackers are leveraging obfuscated PowerShell command lines to dynamically invoke cmdlets via array index values of exported module commands, effectively bypassing signature-based detection for sensitive function names.
date: "2026-10-06T13:10:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - execution
  - stealth
  - obfuscation
  - powershell
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This technique is used to evade detections that look for explicit strings such as Invoke-RestMethod or Invoke-Expression.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: Detects PowerShell processes invoked with obfuscated command lines that enumerate Microsoft.PowerShell.Utility exported commands and invoke cmdlets indirectly by array index.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_powershell_cmdlet_invocation_via_exported_commands_array_index.yml
  - https://www.linkedin.com/posts/mark-o-halloran1_clickfix-defense-evasion-tactic-today-i-ugcPost-7453463467736408064-snrp/
rules:
  - title: Detect PowerShell Dynamic Module Invocation via Array Indexing
    description: Detects PowerShell processes invoking cmdlets indirectly by array index after enumerating module exports, used to evade string-based detection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1027.010
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Source provided specific detection logic for this evasion technique
  hunt_leads:
    - lead: Search command-line logs for 'ExportedCommands.Values' patterns
      technique_id: T1027.010
      data_needed:
        - Process creation (CommandLine)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Technique relies on querying ExportedCommands to facilitate obfuscated invocation
---

This technique involves a stealthy method of PowerShell command execution where attackers avoid invoking sensitive cmdlets, such as 'Invoke-Expression' or 'Invoke-RestMethod', directly by name. Instead, the actor enumerates the 'ExportedCommands' property of the 'Microsoft.PowerShell.Utility' module, converts these commands into an indexed array, and invokes the desired functionality using the integer index of the command. 

By utilizing index-based access, the malicious payload is obfuscated within the command line, rendering string-based detection rules ineffective. This method is particularly dangerous for defenders who rely heavily on monitoring for specific command-line keywords to identify suspicious script execution. This technique has been observed as a means to achieve code execution while evading standard monitoring controls.

## Attack Chain

1. Attacker prepares a PowerShell script containing the obfuscated index-based invocation logic.
2. The PowerShell engine (powershell.exe or pwsh.exe) is executed on the target endpoint.
3. The script executes 'Get-Module -ListAvailable Microsoft.PowerShell.Utility' to retrieve available cmdlets.
4. The script accesses the 'ExportedCommands.Values' collection to enumerate available functions.
5. The attacker identifies the index corresponding to the target command (e.g., Invoke-WebRequest).
6. The target command is invoked indirectly using the array syntax, such as '& $commandArray[$index]'.
7. The script downloads or executes the final malicious payload, such as a secondary stager or script file.

## Impact

Successful execution allows attackers to execute arbitrary code with the privileges of the PowerShell process, enabling stealthy downloading of malware, secondary stager deployment, or system reconnaissance while bypassing perimeter and endpoint security monitoring.

## Recommendation

Deploy the provided Sigma rule to detect the specific combination of module enumeration and array-indexed command invocation. Enable command-line logging via Sysmon (Event ID 1) or PowerShell Script Block Logging (Event ID 4104) to capture the full, de-obfuscated script content for investigation.
