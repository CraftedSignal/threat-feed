---
title: Monitoring Local User Account Creation on Windows
slug: 2026-10-windows-local-account-creation
description: Detection of unauthorized local user account creation on Windows systems via event ID 4720, a technique frequently leveraged by threat actors for persistence and privilege escalation.
date: "2026-10-12T18:03:24Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - windows
  - security-audit
  - t1136.001
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    evidence: Adversaries frequently perform this action to establish persistence or facilitate privilege escalation.
    confidence_band: high
rules:
  - title: Detect Windows Local Account Creation
    description: Detects the creation of a new local user account on a Windows system using event ID 4720.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1136.001
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
    - action: Deploy event 4720 monitoring rule to production SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Source document identifies event ID 4720 as the primary indicator for this TTP
  hunt_leads:
    - lead: Search historical logs for Event ID 4720 to identify unauthorized accounts created in the last 30 days
      technique_id: T1136.001
      data_needed:
        - Windows Event Log Security
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: The detection is intended to identify unauthorized local account creation
  mitigation_plan:
    - priority: short_term
      action: Enable Group Management Audit Logs on all endpoints
      owner: IT Operations
      addresses: T1136.001
      evidence: How_to_implement section of the source content
---

The creation of local user accounts on Windows systems is a common post-exploitation activity used by adversaries to establish persistence or facilitate lateral movement and privilege escalation. Monitoring for this behavior is essential for security operations centers to identify unauthorized access attempts. This activity is logged via Windows Security Audit event ID 4720. While legitimate administrative actions may trigger this event, such occurrences are often anomalous and should be thoroughly investigated. Defenders should verify new account creation against known administrative change windows. Due to potential noise, organizations may choose to tune the detection logic by excluding Domain Controllers or focusing on high-value, critical infrastructure systems.

## Impact

Successful exploitation of this technique allows an attacker to maintain persistent access to a compromised host, bypass original credential requirements, or escalate privileges within the environment. If left undetected, this can lead to unauthorized access to sensitive systems and data, potentially facilitating further lateral movement throughout the enterprise network.

## Recommendation

- Enable Group Management Audit logs in the Local Windows Security Policy to ensure event ID 4720 is generated.
- Implement the detection rule provided below to flag new local user account creation in your SIEM.
- Establish a workflow to verify all triggered alerts with system administrators to filter out legitimate account provisioning.
- Consider creating an exclusion list for known service accounts or administrative task automation to reduce false positives.
