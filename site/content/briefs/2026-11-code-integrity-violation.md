---
brief_id: brief-2026-11-10-code-integrity-violation
event_id: brief-2026-11-10-code-integrity-violation
revision: 1
activity_at: "2026-11-10T03:35:39Z"
title: Windows Code Integrity Policy Violations
slug: 2026-11-code-integrity-violation
description: This brief covers the detection of blocked image or driver load events that fail to meet Windows Defender Application Control (WDAC) signing level requirements.
date: "2026-11-10T03:35:39Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
tags:
  - windows
  - security-monitoring
  - edr
  - persistence
affected_os:
  - Windows
references:
  - https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/event-id-explanations
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/code_integrity/win_codeintegrity_enforced_policy_block.yml
rules:
  - title: Detect Windows Code Integrity Policy Block (Event ID 3077)
    description: Detects blocked load events that did not meet the authenticode signing level requirements or violated the code integrity policy.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1543
    data_sources:
      - image_load
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
    - SOC
  hunt_leads:
    - lead: Identify high-frequency Event ID 3077 occurrences per host to detect potential persistence attempts
      technique_id: T1543
      data_needed:
        - CodeIntegrity-Operational Event ID 3077
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Source documentation identifies Event 3077 as a block event for policy violations.
  mitigation_plan:
    - priority: medium
      action: Review and audit existing WDAC policies to ensure valid business drivers are signed correctly
      owner: IT Operations
      addresses: Code Integrity policy violations
      evidence: Operational logs confirm policy enforcement blocks.
---

Windows Defender Application Control (WDAC) and Code Integrity mechanisms monitor for unauthorized code execution. Event ID 3077 is generated when the system blocks an image or kernel-mode driver from loading because it does not meet the enforced policy signing level requirements or explicitly violates a configured Code Integrity policy. This telemetry is indicative of either misconfigured legitimate software, local policy conflicts, or attempts by an attacker to load unsigned or malicious drivers to gain kernel-level persistence.

## Recommendation

* Enable the "Microsoft-Windows-CodeIntegrity/Operational" event log channel across all Windows endpoints to capture Event ID 3077.
* Investigate occurrences of Event ID 3077 to determine if the blocked file is a legitimate business application that requires an updated policy or a malicious attempt to load an unauthorized driver.
* Deploy the Sigma rule provided below to SIEM platforms to centralize monitoring of policy violations.
