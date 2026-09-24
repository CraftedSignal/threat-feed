---
title: Detection of PowerShell Alias Cmdlet Misuse for Obfuscation
slug: 2026-09-powershell-alias-obfuscation
description: Adversaries use Set-Alias and New-Alias cmdlets in PowerShell to rename standard commands, obfuscating malicious scripts to bypass security monitoring and automated analysis.
date: "2026-09-24T12:12:58Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - obfuscation
  - powershell
  - stealth
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Detects Set-Alias or New-Alias cmdlet usage which can be used as a mean to obfuscate PowerShell scripts.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: Detects Set-Alias or New-Alias cmdlet usage which can be used as a mean to obfuscate PowerShell scripts.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_set_alias.yml
  - https://github.com/1337Rin/Swag-PSO
rules:
  - title: Potential PowerShell Obfuscation Using Alias Cmdlets
    description: Detects the use of Set-Alias or New-Alias cmdlets which can be used to obfuscate PowerShell script intent by masking command names.
    platform: sigma
    severity: low
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
  priority: monitor_or_close
  owners:
    - Detection Engineering
  hunt_leads:
    - lead: Search for high volumes of Set-Alias or New-Alias events in environment
      technique_id: T1059.001
      data_needed:
        - Event ID 4104 logs
      priority: low
      confidence: low
      disposition: convert_to_detection
      evidence: Source document indicates usage for obfuscation
---

Threat actors frequently employ PowerShell obfuscation techniques to conceal their intent from security analysts and automated detection tools. A common method involves using the 'Set-Alias' or 'New-Alias' cmdlets to assign arbitrary names to built-in PowerShell commands. By mapping malicious or common system functions to non-standard names, attackers can render script analysis significantly more difficult, as traditional static analysis rules looking for specific cmdlet names will fail to identify the true command being executed. This technique is often seen in early-stage malware loaders and script-based droppers aiming to evade detection during the initial execution phase. Defenders should prioritize visibility into script block content to monitor for these redirection patterns.

## Attack Chain

1. Attacker develops a malicious PowerShell script intended for target execution.
2. Attacker uses 'Set-Alias' or 'New-Alias' to create aliases for sensitive cmdlets like 'Invoke-Expression' or 'DownloadString'.
3. The obfuscated script is delivered to the target environment via email attachments or document macros.
4. The malicious script block is executed by the target user or a compromised process.
5. PowerShell Script Block Logging (Event ID 4104) captures the execution of the alias definitions.
6. The script continues execution using the redefined aliases to perform system discovery or C2 communication.
7. The final objective, such as credential theft or lateral movement, is achieved while maintaining script stealth.

## Impact

The use of alias-based obfuscation increases the risk of successful execution of malicious PowerShell payloads, as it reduces the efficacy of basic signature-based detection. This stealth can lead to undetected command execution, persistence, and potential data exfiltration within an enterprise environment.

## Recommendation

* Enable PowerShell Script Block Logging (Event ID 4104) via Group Policy to capture the full content of executing scripts.
* Deploy the provided Sigma rule to your SIEM to monitor for 'Set-Alias' and 'New-Alias' usage, and tune out known-legitimate CIM-related aliases.
* Centralize and ingest PowerShell operational logs into a log management system for historical script analysis.
