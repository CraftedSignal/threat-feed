---
brief_id: brief-2026-10-sensitive-audit-policy-disabled
event_id: brief-2026-10-sensitive-audit-policy-disabled
revision: 1
activity_at: "2026-10-20T16:24:48Z"
title: 'Windows: Security-sensitive audit policy sub-category disabled'
slug: 2026-10-sensitive-audit-policy-disabled
description: Attackers disable security-sensitive audit policy subcategories on Windows systems to evade detection and impair forensic capabilities by preventing the logging of critical activities.
date: "2026-10-20T16:24:48Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - windows
  - defense-evasion
  - forensic-tampering
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    subtechnique_id: T1070.001
    subtechnique_name: Clear Windows Event Logs
    evidence: Adversaries can tamper, clear, and delete this data to break SIEM detections, cover their tracks, and slow down incident response.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    subtechnique_id: T1562.002
    subtechnique_name: Disable Windows Event Logging
    evidence: Identifies when a security-sensitive audit policy subcategory is disabled and left disabled.
    confidence_band: high
rules:
  - title: Detect Sensitive Audit Policy Sub-Category Disabled
    description: Detects when sensitive Windows audit policy subcategories are disabled, which may indicate anti-forensics activity by an attacker.
    platform: sigma
    severity: medium
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
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable Audit Policy Change auditing on critical systems
      owner: IT Operations
      due: 72h
      evidence: Setup instructions referenced in source
    - action: Deploy Sigma rule for Event 4719 filtering on sensitive subcategories
      owner: Detection Engineering
      due: 48h
      evidence: Rule definition in content
  hunt_leads:
    - lead: Historical Event ID 4719 logs showing subcategory removal
      technique_id: T1562.002
      data_needed:
        - Windows Security Event Logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Adversaries can tamper with audit logs to cover tracks
  mitigation_plan:
    - priority: medium
      action: Implement granular GPO-based audit policy enforcement to prevent unauthorized modification
      owner: IT Operations
      addresses: T1562
      evidence: Defense evasion technique mitigation
---

Adversaries often target Windows audit policies to blind security teams and hinder incident response efforts. By disabling specific audit policy subcategories, attackers can suppress logs for critical security events, such as process creation, logon events, and security group management. This anti-forensics activity aims to evade SIEM detections and conceal post-compromise behaviors. Defenders should monitor for Windows Event ID 4719, which records changes to the system's audit policy. This brief focuses on detecting instances where a sensitive subcategory is disabled and remains in a disabled state, indicating potential malicious tampering rather than routine administrative activity.

## Attack Chain

1. Attacker gains administrative access to the target host.
2. Attacker identifies critical audit policy subcategories to target (e.g., Process Creation, Logon).
3. Attacker uses command-line utilities like `auditpol.exe` or group policy modifications to alter audit settings.
4. System generates a Windows Event ID 4719 signifying an audit policy change.
5. If the change removes Success or Failure auditing, the attacker successfully suppresses future logs.
6. Attacker proceeds with malicious actions (e.g., lateral movement, credential theft) without generating security logs.
7. Final objective is maintained stealth during the mission duration.

## Impact

Successful modification of audit policies results in critical visibility gaps for security operations centers. If security-relevant logs are disabled, incident responders cannot reconstruct the timeline of an intrusion, identify compromised accounts, or determine the scope of a breach. This enables attackers to persist within the environment undetected for extended periods.

## Recommendation

* Enable Windows Security Event logging for Event ID 4719 across all workstations and servers.
* Implement the provided detection logic to alert on the removal of audit policy success logging for sensitive subcategories like "Process Creation" and "Logon".
* Investigate any account or process identified in Event ID 4719 triggers to verify if the modification was a result of authorized administrative maintenance or malicious intent.
* Maintain a baseline of intended audit policies via Group Policy or MDM to facilitate the detection of unauthorized drifts.
