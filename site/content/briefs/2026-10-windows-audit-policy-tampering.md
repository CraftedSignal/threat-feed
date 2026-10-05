---
title: Detection of Windows Audit Policy Tampering via Event ID 4719
slug: 2026-10-windows-audit-policy-tampering
description: Adversaries may disable critical Windows audit policies to evade detection by monitoring tools, an activity identifiable through the analysis of Event ID 4719.
date: "2026-10-05T18:02:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - audit-tampering
  - windows-security
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows Server
  - Windows 10
  - Windows 11
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: The analytic detects the disabling of important audit policies... as it suggests an attacker may have gained access... and is attempting to evade detection.
    confidence_band: high
rules:
  - title: Detect Disabling of Important Windows Audit Policies
    description: Detects when critical success or failure audit policies are disabled on a Windows system by monitoring Event ID 4719.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.002
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
    - action: Enable 'Audit Audit Policy Change' subcategory via GPO.
      owner: IT Operations
      due: 72h
      evidence: Required for detection of Event ID 4719.
  hunt_leads:
    - lead: Search for Event ID 4719 in historical logs.
      technique_id: T1562.002
      data_needed:
        - Windows Event Logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Audit policy tampering is a high-signal indicator of unauthorized access.
  mitigation_plan:
    - priority: medium
      action: Restrict administrative access to GPO and audit policy configuration.
      owner: IT Operations
      addresses: T1562.002
      evidence: Limits unauthorized modification of security policies.
---

Attackers who gain administrative access to a host, particularly domain controllers, often seek to disable security auditing to mask their post-exploitation activities. This technique allows adversaries to perform actions like privilege escalation, lateral movement, or data exfiltration without generating logs that would alert defenders. This detection focuses on Windows Security Event ID 4719, which is generated when a system audit policy is changed. Defenders should monitor for instances where success or failure auditing for critical subcategories is removed. Because these changes are rare in a well-managed production environment, they serve as high-fidelity indicators of potential compromise or insider threat activity.

## Impact

Successful tampering with audit policies allows an attacker to operate undetected, leading to significant risks such as full domain compromise, undetected persistence, and unauthorized data access. If an attacker disables audit policies, the SOC may lose visibility into the entire attack lifecycle, preventing effective incident response and forensic investigation.

## Recommendation

- Enable the "Audit Audit Policy Change" subcategory in your Group Policy settings to ensure Windows records these modifications.
- Implement log ingestion for Windows Security Event ID 4719 across all endpoints and domain controllers.
- Establish a baseline of legitimate audit policy changes in your environment to tune the detection logic and suppress false positives from legitimate administrative tasks.
- Deploy the provided detection logic to monitor for removals of critical subcategories identified by your security team.
