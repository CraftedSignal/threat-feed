---
brief_id: brief-2026-11-08-non-interactive-powershell
event_id: brief-2026-11-08-non-interactive-powershell
revision: 1
activity_at: "2026-11-08T02:14:26Z"
title: 'Windows: Non-interactive PowerShell process execution'
slug: 2026-11-non-interactive-powershell
description: Detection logic for identifying non-interactive PowerShell execution patterns by monitoring parent-child process relationships.
date: "2026-11-08T02:14:26Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Validated against SigmaHQ rule structure
tags:
  - windows
  - powershell
  - detection
  - execution
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.001
    subtechnique_name: PowerShell
    evidence: Detects non-interactive PowerShell activity by looking at the powershell process with a non-user GUI process such as explorer.exe as a parent.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_powershell_non_interactive_execution.yml
  - https://web.archive.org/web/20200925032237/https://threathunterplaybook.com/notebooks/windows/02_execution/WIN-190410151110.html
rules:
  - title: Non Interactive PowerShell Process Spawned
    description: Detects non-interactive PowerShell activity by looking at the powershell process with parent processes that are typically not associated with user-interactive GUI sessions.
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule as an informational hunt rule to baseline environment noise.
      owner: Detection Engineering
      due: 7d
      evidence: Rule provides low-fidelity signal due to expected administrative script usage.
---

This brief provides detection logic for identifying PowerShell (powershell.exe) or PowerShell Core (pwsh.exe) processes initiated without a standard user-interactive parent. While legitimate administrative and maintenance scripts often exhibit this behavior, it is a common technique used for obfuscated or automated execution of malicious payloads. Defenders should establish a baseline of expected parent processes before alerting.

## Recommendation

* Deploy the provided Sigma rule to identify PowerShell activity that deviates from common administrative or update-related parent processes.
* Baseline the parent processes of PowerShell in your environment and maintain an allowlist to reduce noise from legitimate management tools.
* Prioritize investigation of PowerShell processes spawned by non-standard parent processes, particularly those involving uncommon or unknown binary paths.
