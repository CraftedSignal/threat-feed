---
title: Suspicious PowerShell Start-Process PassThru Usage
slug: 2026-09-suspicious-start-process
description: Detection logic for PowerShell scripts utilizing the Start-Process cmdlet with the -PassThru parameter to execute processes in the background, a technique often used for stealthy execution.
date: "2026-09-03T13:43:01Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - stealth
  - powershell
  - execution
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The rule maps to T1036.003 for potential stealthy process execution.
    confidence_band: med
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_start_process.yml
  - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process?view=powershell-7.6
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1036.003/T1036.003.md
rules:
  - title: Suspicious Start-Process PassThru
    description: Detects PowerShell scripts using the Start-Process cmdlet with -PassThru and -FilePath to execute processes in the background
    platform: sigma
    severity: medium
    tactics:
      - stealth
    techniques:
      - T1036.003
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104)
      owner: IT Operations
      due: 72h
      evidence: Required for visibility into script execution
  hunt_leads:
    - lead: Search for high frequency of Start-Process calls in Script Block logs
      technique_id: T1036
      data_needed:
        - Event ID 4104
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Heuristic indicators for stealthy process execution
---

This detection brief addresses the use of the PowerShell 'Start-Process' cmdlet (or its alias 'saps') combined with the '-PassThru' and '-FilePath' parameters. Attackers leverage this combination to launch malicious processes in the background, allowing them to remain detached from the parent shell while maintaining the ability to capture process objects. This technique is frequently observed in post-exploitation scenarios where adversaries attempt to maintain persistence or execute lateral movement tools stealthily. While this cmdlet is a standard management tool, its usage in scripts to trigger background operations without interactive user oversight warrants monitoring, especially when utilized within obfuscated or encoded PowerShell blocks.

## Impact

Successful abuse of this technique allows an attacker to spawn hidden or detached malicious processes that bypass standard shell interaction, facilitating persistence, credential dumping, or command-and-control communication while complicating traditional session-based monitoring.

## Recommendation

Detection engineering teams should focus on PowerShell Script Block Logging (Event ID 4104) to capture the execution of the identified parameters.

* Deploy the provided Sigma rule to identify scripts executing 'Start-Process' with '-PassThru' and '-FilePath'.
* Enable PowerShell Script Block Logging across the enterprise to ensure the necessary telemetry is available for analysis.
* Establish an allowlist for known, legitimate administrative scripts that utilize this cmdlet to reduce false positives in a SOC environment.
