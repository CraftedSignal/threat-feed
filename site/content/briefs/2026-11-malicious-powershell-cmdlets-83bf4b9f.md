---
brief_id: brief-2026-11-10-malicious-powershell-cmdlets-83bf4b9f
event_id: brief-2026-11-10-malicious-powershell-cmdlets-83bf4b9f
revision: 1
activity_at: "2026-11-10T05:38:29Z"
title: Malicious PowerShell Commandlets in Exploitation Frameworks
slug: 2026-11-malicious-powershell-cmdlets-83bf4b9f
description: Detection of PowerShell commandlets commonly utilized within post-exploitation frameworks to perform credential dumping, lateral movement, and system reconnaissance.
date: "2026-11-10T05:38:29Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
tags:
  - windows
  - powershell
  - execution
  - discovery
  - post-exploitation
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_powershell_malicious_cmdlets.yml
rules:
  - title: Detect Malicious PowerShell Commandlets
    description: Detects execution of PowerShell commandlets commonly used in offensive security and post-exploitation frameworks.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection for commandlet names
      owner: Detection Engineering
      due: 48h
      evidence: Source lists common commandlets found in exploitation frameworks.
  hunt_leads:
    - lead: Hunt for rare PowerShell commandlets in process execution logs
      technique_id: T1059.001
      data_needed:
        - Process command line arguments
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: High volume of offensive tool usage relies on these specific function names.
---

This brief highlights a collection of PowerShell commandlets associated with well-known offensive security and exploitation frameworks. These commandlets are frequently observed in post-exploitation scenarios, including credential harvesting (e.g., Mimikatz wrappers), privilege escalation, and domain reconnaissance. Defenders should monitor for the execution of these specific function names within PowerShell process command lines.

## Recommendation
- Deploy the provided Sigma rule to detect the execution of known offensive PowerShell commandlets.
- Baseline PowerShell usage in your environment to identify legitimate administrative scripts that may utilize similarly named functions.
- Enable Script Block Logging (Event ID 4104) to capture the full execution context, as command line arguments can be obfuscated or truncated in standard process-creation logs.
