---
title: Detection of AppLocker Policy Bypass Attempts
slug: 2026-10-applocker-bypass
description: This detection identifies potential defense evasion and privilege escalation by monitoring Windows AppLocker for repeated execution block events indicating unauthorized software usage.
date: "2026-10-05T12:17:29Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - privilege-escalation
  - applocker
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: The analytic is designed to identify attempts to bypass these restrictions, which could be indicative of an attacker attempting to escalate privileges.
    confidence_band: high
references:
  - https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/querying-application-control-events-centrally-using-advanced-hunting
  - https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/using-event-viewer-with-applocker
rules:
  - title: Detect Repeated AppLocker Policy Block Events
    description: Detects 5 or more AppLocker block events on a single host within the event log timeframe, indicating potential policy bypass attempts.
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
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection and monitor for hosts exceeding the event threshold.
      owner: Detection Engineering
      due: 48h
      evidence: Analytic relies on thresholding multiple events.
  mitigation_plan:
    - priority: medium_term
      action: Review AppLocker policies to ensure least privilege and account for legitimate business software.
      owner: IT Operations
      evidence: AppLocker management guidelines.
---

Windows AppLocker is an application control feature designed to restrict the execution of unauthorized software. Threat actors attempting to escalate privileges or establish persistence often attempt to execute binaries, scripts, or installers that are explicitly blocked by security policies. When these attempts occur, AppLocker generates specific operational logs. 

This threat brief focuses on identifying repeated AppLocker block events (Event IDs 8007, 8004, 8022, 8025, 8029, and 8040). An accumulation of five or more block events on a single host serves as a high-fidelity indicator that an unauthorized user or process is attempting to circumvent established security boundaries. Defenders should monitor for these events to detect potential reconnaissance or exploitation attempts where an adversary is testing policy restrictions or attempting to execute malicious payloads in a restricted environment.

## Impact

Successful bypass of application control policies can allow adversaries to execute unauthorized tools, escalate privileges, or maintain persistence on compromised endpoints. Repeated attempts indicate persistent effort to circumvent security controls, which often precedes malicious activity such as credential theft or data exfiltration.

## Recommendation

Detection engineering teams should ingest Microsoft-Windows-AppLocker/EXE and DLL, MSI and Script, and Packaged app-Deployment operational event logs into their SIEM. 

* Deploy the provided Sigma rule to alert on hosts where AppLocker block events exceed a threshold of five occurrences within the ingestion window.
* Investigate the associated FilePath and TargetUser fields to determine if the activity represents a legitimate user error or a deliberate attempt to bypass security policies.
* Tune the threshold based on the baseline volume of legitimate blocked execution attempts in the environment.
