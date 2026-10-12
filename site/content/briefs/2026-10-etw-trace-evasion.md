---
title: ETW Trace Evasion Activity
slug: 2026-10-etw-trace-evasion
description: Adversaries manipulate Event Tracing for Windows (ETW) using built-in administration tools to disable providers and clear logs, effectively blinding security telemetry and evading detection.
date: "2026-10-12T14:33:50Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - defense-impairment
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: Adversaries may target ETW to blind security tooling and evade detection by removing visibility into process activity.
    confidence_band: high
rules:
  - title: Detect ETW Trace Evasion Activity
    description: Detects command line activity that attempts to tamper with Event Tracing for Windows (ETW) by clearing or disabling trace logs or providers.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
    techniques:
      - T1070
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma rule to monitor administrative binary command lines
      owner: Detection Engineering
      due: 24h
      evidence: SigmaHQ rule logic
  hunt_leads:
    - lead: Search logs for command line usage of wevtutil.exe, logman.exe, or Set-EtwTraceProvider
      technique_id: T1070
      data_needed:
        - Process creation telemetry
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source documentation of evasion tools
  mitigation_plan:
    - priority: medium_term
      action: Enforce strict execution policies on administrative binaries
      owner: IT Operations
      addresses: T1070
      evidence: Defense impairment reduction
---

Adversaries frequently target Event Tracing for Windows (ETW) to compromise the visibility of security products. By manipulating logging configurations and trace sessions, attackers can suppress the generation of logs that would otherwise capture malicious process activity, network connections, or credential access. This activity leverages legitimate administrative binaries such as wevtutil.exe, logman.exe, and PowerShell cmdlets to modify, disable, or remove ETW providers. Because these are built-in Windows features, this technique provides a stealthy method for adversaries to impair defensive capabilities without needing to drop custom malware. Defending against this activity requires monitoring for specific command-line parameters associated with administrative log management that deviate from standard maintenance cycles.

## Attack Chain

1. Attacker gains initial access or code execution on the target endpoint.
2. Attacker enumerates active trace providers or logs to identify targets for suppression using logman or get-log commands.
3. Attacker uses wevtutil.exe to clear event logs containing trace data.
4. Attacker uses wevtutil.exe with the /e:false switch to disable targeted event logs.
5. Attacker utilizes logman.exe to update existing trace sessions and remove specific providers.
6. Attacker leverages PowerShell cmdlets such as Remove-EtwTraceProvider to unregister ETW trace providers.
7. Attacker employs Set-EtwTraceProvider to modify provider properties (e.g., setting flags to 0x11 or 17) to disable logging triggers.
8. Final objective of blinding security telemetry is achieved, allowing for subsequent lateral movement or data exfiltration without alerting defenders.

## Impact

Successful evasion of ETW logging results in significant gaps in defensive visibility. SOC analysts lose the ability to reconstruct malicious activity, as critical telemetry regarding process creation, file modifications, and network connections may be suppressed. This impacts incident response by delaying detection and hindering forensic analysis, potentially allowing persistent threats to operate undetected within the environment for extended periods.

## Recommendation

1. Deploy the Sigma rules provided below to detect suspicious use of administrative utilities for log manipulation.
2. Enable process-creation logging (Sysmon Event ID 1) across all Windows endpoints to capture command-line arguments.
3. Baseline administrative usage of wevtutil.exe and logman.exe to identify deviations from standard IT management behavior.
4. Restrict non-administrator accounts from executing binaries that manage event logs and tracing sessions.
