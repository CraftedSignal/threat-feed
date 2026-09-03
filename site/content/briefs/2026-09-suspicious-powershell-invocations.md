---
title: Suspicious PowerShell Command Pattern Detection
slug: 2026-09-suspicious-powershell-invocations
description: This brief documents patterns of PowerShell invocation commonly associated with malicious activities such as payload downloading, fileless execution, and persistence establishment.
date: "2026-09-03T12:35:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - windows
  - powershell
  - execution
  - persistence
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Detects suspicious PowerShell invocation command parameters.
    confidence_band: high
rules:
  - title: Detect Suspicious PowerShell Invocation Patterns
    description: Detects multiple patterns of suspicious PowerShell invocation, including base64 encoded command execution, registry persistence modification, and remote payload downloading.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - ps_module
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule to the SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Rule mapping to common post-exploitation PowerShell patterns
  hunt_leads:
    - lead: Search for high-frequency hidden PowerShell executions
      technique_id: T1059.001
      data_needed:
        - Event ID 4103 / 4104
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Source documents patterns of hidden execution
---

This brief outlines specific PowerShell invocation command patterns identified via PowerShell Module logging (Event ID 4103). These patterns are frequently observed in post-exploitation scenarios, including the use of encoded commands, network-based file downloads via WebClient, and the manipulation of Windows Registry Run keys for persistence. These techniques allow attackers to execute arbitrary code directly in memory or establish stealthy persistence mechanisms that survive system reboots. Defenders should monitor for combinations of flags that reduce logging visibility or bypass execution policies, such as the simultaneous use of '-nop' (NoProfile), '-w hidden' (WindowStyle Hidden), and network-related objects. 

## Impact

Successful exploitation of these patterns enables unauthorized code execution, credential harvesting, lateral movement, and long-term persistence within a target environment. By bypassing default execution policies, adversaries can execute sophisticated multi-stage malware, infostealers, or ransomware components without relying on traditional dropped binaries.

## Recommendation

- Deploy the provided Sigma rule to your SIEM to monitor PowerShell Module logging (Event ID 4103).
- Prioritize alerts containing combinations of 'System.Net.WebClient' and 'Download' as these indicate potential stages for remote malware retrieval.
- Tune the detection logic by filtering for legitimate administrative or software deployment scripts, such as those used by Chocolatey.
- Enable Script Block Logging (Event ID 4104) in conjunction with Module Logging to capture the full de-obfuscated script content if the command line is obfuscated.
