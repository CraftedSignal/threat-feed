---
title: PowerShell AppLocker Policy Discovery via Get-AppLockerPolicy
slug: 2026-08-powershell-applocker-discovery
description: Detection of adversarial reconnaissance activities leveraging the Get-AppLockerPolicy PowerShell cmdlet to map host-based application execution restrictions.
date: "2026-08-18T23:52:20Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - discovery
  - system-reconnaissance
  - powershell
  - applocker
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1518
    technique_name: Software Discovery
    evidence: Detects AppLocker policy enumeration attempts via PowerShell using the Get-AppLockerPolicy cmdlet.
    confidence_band: high
rules:
  - title: Detect PowerShell AppLocker Policy Discovery
    description: Detects AppLocker policy enumeration attempts via PowerShell using the Get-AppLockerPolicy cmdlet and a policy scope of Effective, LDAP, or Local.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1518.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  hunt_leads:
    - lead: Search historical logs for Get-AppLockerPolicy usage to establish a baseline of administrative activity.
      technique_id: T1518.001
      data_needed:
        - Process command line logging
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Source provides specific command line flags for policy enumeration.
---

Adversaries often perform reconnaissance within a compromised environment to understand existing security controls before attempting to deploy secondary payloads or move laterally. A specific technique observed involves the use of native Windows PowerShell administrative cmdlets to query AppLocker policies. By executing the Get-AppLockerPolicy cmdlet with specific flags such as -Effective, -Ldap, or -Local, an attacker can determine which applications are permitted or blocked from execution. This information allows an adversary to tailor their subsequent execution techniques to bypass security restrictions or confirm if their target binaries are permitted to run. Defenders should monitor for these specific command-line patterns, as they often deviate from standard user activity and indicate preparation for further malicious activity.

## Impact

Successful reconnaissance enables an attacker to refine their post-exploitation strategy by identifying gaps in execution control, potentially leading to successful privilege escalation, persistence establishment, or execution of malicious tools that would otherwise be blocked.

## Recommendation

Deploy the provided Sigma rule to monitor for suspicious invocation of AppLocker policy cmdlets. Because this activity is common in administrative troubleshooting, focus initial implementation on baseline discovery before applying blocking or high-alerting thresholds. Enable PowerShell Script Block Logging (Event ID 4104) and Sysmon Process Creation (Event ID 1) to capture the required command-line telemetry.
