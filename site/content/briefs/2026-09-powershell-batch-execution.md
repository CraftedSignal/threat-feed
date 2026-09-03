---
title: Detection of PowerShell Executing Batch Scripts
slug: 2026-09-powershell-batch-execution
description: Adversaries often abuse PowerShell to invoke batch files, allowing for sequential command execution and complex logic within the Windows environment.
date: "2026-09-03T13:42:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - execution
  - powershell
  - batch
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: 'Batch files (ex: .bat or .cmd) also provide the shell with a list of sequential commands to run.'
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_execute_batch_script.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1059.003/T1059.003.md#atomic-test-1---create-and-execute-batch-script
rules:
  - title: Detect PowerShell Executing Batch Script
    description: Detects the use of Start-Process in PowerShell to execute .bat or .cmd files, a common technique for command shell abuse.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM
      owner: Detection Engineering
      due: 72h
      evidence: Required to identify T1059.003 execution patterns
  mitigation_plan:
    - priority: medium_term
      action: Enforce PowerShell Constrained Language Mode where appropriate
      owner: IT Operations
      addresses: General script abuse
      evidence: Defense-in-depth practice to restrict arbitrary execution
---

Adversaries frequently leverage the Windows command shell and PowerShell to execute batch scripts (typically with .bat or .cmd extensions) as part of their post-exploitation activities. This technique allows attackers to run lists of sequential commands, perform repetitive system tasks, or implement complex logic such as conditionals and loops under the context of an existing PowerShell session. Because batch files can be used to facilitate both legitimate administrative tasks and malicious activity, monitoring the invocation of these scripts via PowerShell is essential for identifying unauthorized execution patterns. Detection engineers should focus on PowerShell Script Block Logging (Event ID 4104) to capture the full command context when Start-Process is used to trigger these scripts.

## Impact

Successful execution of malicious batch scripts can lead to full system compromise, lateral movement, or the execution of additional staged payloads. If undetected, attackers can maintain persistence or execute automated tasks across multiple systems within an enterprise network.

## Recommendation

* Enable Windows PowerShell Script Block Logging (Event ID 4104) across all endpoints to ensure the full content of executed scripts is captured in logs.
* Deploy the provided Sigma rule to your SIEM to monitor for PowerShell scripts attempting to launch .bat or .cmd files.
* Establish a baseline for administrative scripts used in your environment to tune out false positives originating from legitimate system management activity.
