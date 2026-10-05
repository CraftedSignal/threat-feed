---
title: Detection of Windows AppLocker Policy Violations
slug: 2026-10-windows-applocker-violations
description: This brief describes the identification of Windows AppLocker policy violations, which may indicate adversary efforts to bypass application execution controls or execute unauthorized code.
date: "2026-10-05T18:01:47Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - windows
  - defense-evasion
  - application-control
  - endpoint-security
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: The analytic detects attempts to bypass application restrictions by identifying Windows AppLocker policy violations.
    confidence_band: high
rules:
  - title: Detect Windows AppLocker Block Events
    description: Detects attempts to execute unauthorized applications or scripts by identifying Windows AppLocker policy violation events.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218
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
    - action: Enable AppLocker event logging in group policy objects
      owner: IT Operations
      due: 72h
      evidence: Source requirement for log ingestion
  hunt_leads:
    - lead: High frequency of AppLocker 8007 events from a single workstation
      technique_id: T1218
      data_needed:
        - AppLocker event logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: AppLocker blocks may indicate adversary probing
  mitigation_plan:
    - priority: short_term
      action: Review AppLocker policy effectiveness
      owner: IT Operations
      addresses: T1218
      evidence: Policy violations occur when controls are active
---

Windows AppLocker is an application control mechanism designed to restrict the software and scripts that users are permitted to run. The monitoring of AppLocker block events is essential for security operations teams to detect attempts at policy circumvention or unauthorized software execution. Adversaries often attempt to run non-approved binaries, scripts, or installer files to establish persistence or facilitate secondary payload execution. 

When AppLocker is configured to block unauthorized activity, it generates specific event codes within the Microsoft-Windows-AppLocker/MSI and Script or EXE and DLL event logs. By ingesting and analyzing EventCodes 8007, 8004, 8022, 8025, 8029, and 8040, defenders can identify instances where execution requests were denied. This visibility is critical for catching defense evasion techniques where an attacker attempts to execute payloads in restricted environments, potentially preventing further system compromise or data exfiltration.

## Impact

The primary impact of these events is the identification of potential policy circumvention, which could lead to unauthorized code execution, privilege escalation, or persistence if an attacker successfully finds a bypass or misconfiguration. While often benign due to administrative or user error, repeated or unusual blocks on high-value systems can indicate an active threat actor attempting to weaponize local binaries or unauthorized scripts.

## Recommendation

Detection engineering teams should prioritize the ingestion of AppLocker event logs to monitor for unauthorized execution attempts.

* Enable and ingest Windows AppLocker event logs (Microsoft-Windows-AppLocker) into the SIEM, specifically focusing on EventIDs 8007, 8004, 8022, 8025, 8029, and 8040.
* Deploy the Sigma rule provided below to trigger alerts when AppLocker blocks execution attempts.
* Tune the alerts to exclude known administrative maintenance windows or deployment scripts to reduce noise.
* Investigate the associated FilePath and user context for any blocked execution events to determine if the activity represents a genuine security threat or a legitimate user error.
