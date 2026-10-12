---
title: PowerShell ETW Trace Disabling Techniques
slug: 2026-10-etw-evasion-powershell
description: Adversaries utilize PowerShell cmdlets to disable or modify Event Tracing for Windows (ETW) providers to impair security visibility and evade detection.
date: "2026-10-12T14:33:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - evasion
  - defense-impairment
  - powershell
  - windows
  - security-visibility
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: Adversaries utilize PowerShell cmdlets to disable or remove ETW trace sessions.
    confidence_band: high
rules:
  - title: Detect ETW Trace Provider Manipulation via PowerShell
    description: Detects usage of PowerShell cmdlets such as Remove-EtwTraceProvider or Set-EtwTraceProvider to disable or remove ETW trace sessions.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
      - stealth
    techniques:
      - T1070
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all endpoints.
      owner: IT Operations
      due: 48h
      evidence: Required for visibility into PowerShell script block execution.
    - action: Deploy the Sigma rule for ETW manipulation detection.
      owner: Detection Engineering
      due: 24h
      evidence: Rule provided in the brief.
---

Adversaries frequently target Windows Event Tracing (ETW) to blind security monitoring solutions. By leveraging PowerShell cmdlets such as Remove-EtwTraceProvider or Set-EtwTraceProvider, attackers can programmatically disable or modify the configuration of tracing providers. Disabling these providers prevents the logging of sensitive activities, including process creation, network connections, and script execution, which are critical for detecting malicious post-exploitation activity. This technique is typically employed during the late stages of an attack chain to facilitate persistence or long-term data exfiltration without triggering security alerts.

## Impact

Successful suppression of ETW providers results in significant gaps in security telemetry. Defenders lose visibility into script execution and process-related events on compromised hosts. This degradation of observability allows attackers to operate with a reduced risk of detection, effectively neutralizing host-based detection capabilities that rely on ETW-derived event logs.

## Recommendation

1. Deploy the provided Sigma rule to detect attempts to manipulate ETW providers via PowerShell script blocks.
2. Ensure PowerShell Script Block Logging (Event ID 4104) is enabled across the environment to capture the command line content.
3. Review logs for the identified cmdlets and investigate associated processes for unauthorized administrative activity.
