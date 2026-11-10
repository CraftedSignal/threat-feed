---
brief_id: brief-2026-11-10-malicious-powershell-commandlets
event_id: brief-2026-11-10-malicious-powershell-commandlets
revision: 1
activity_at: "2026-11-10T07:45:03Z"
title: Detection of Malicious PowerShell Framework Commandlets
slug: 2026-11-malicious-powershell-commandlets
description: This brief provides detection logic for commandlets associated with various PowerShell-based exploitation frameworks, post-exploitation tools, and persistence mechanisms.
date: "2026-11-10T07:45:03Z"
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
  validation_status: Needs environment validation of script logging coverage.
tags:
  - windows
  - powershell
  - execution
  - discovery
  - persistence
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.001
    subtechnique_name: PowerShell
    evidence: The detection rules target commandlets derived from PowerShell-based exploitation frameworks.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: Multiple tools listed, such as DomainPasswordSpray and BloodHound, are used for account and domain discovery.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_malicious_commandlets.yml
rules:
  - title: Detect Malicious PowerShell Commandlets
    description: Detects commandlet names frequently used in PowerShell-based exploitation frameworks and post-exploitation tools.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - execution
    techniques:
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
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all Windows hosts.
      owner: IT Operations
      due: 48h
      evidence: Required by Sigma rules.
  hunt_leads:
    - lead: Search PowerShell logs for the presence of known-malicious commandlets extracted from the rule list.
      technique_id: T1059.001
      data_needed:
        - PowerShell Event ID 4104
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: High volume of offensive script blocks documented in the Sigma rule.
---

This brief summarizes signatures for identifying malicious PowerShell script blocks. These commandlets are frequently observed in offensive security frameworks, credential theft tools, and backdoor installers. The detection focuses on identifying specific function names within PowerShell Script Block Logging events.

## Recommendation
- Enable PowerShell Script Block Logging (Event ID 4104) across all Windows endpoints.
- Deploy the provided Sigma rule to your SIEM to monitor for known offensive commandlets.
- Review any detections for legitimate administrative scripts or internal tooling; tune by filtering out known-good, internally-developed script paths.
