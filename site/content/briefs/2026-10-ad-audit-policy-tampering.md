---
title: Detection of Active Directory Audit Policy Tampering
slug: 2026-10-ad-audit-policy-tampering
description: Detection of unauthorized removal of success or failure audit policies on Domain Controllers, a critical defense evasion tactic used by attackers to hide malicious activity.
date: "2026-10-05T12:14:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - active-directory
  - windows
  - monitoring
vendors:
  - Microsoft
products:
  - Active Directory Domain Services
affected_os:
  - Windows Server
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.001
    technique_name: 'Impair Defenses: Disable or Modify System Firewall'
    evidence: The following analytic detects the disabling of audit policies on a domain controller.
    confidence_band: high
rules:
  - title: Detect AD Domain Controller Audit Policy Disabled
    description: Detects the disabling of success or failure audit policies on a Domain Controller via Windows Event ID 4719.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
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
    - action: Enable and test ingestion of Event ID 4719 in SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Source document highlights Event ID 4719 as the primary detection mechanism.
  hunt_leads:
    - lead: Search historic logs for Event ID 4719 to establish a baseline of authorized changes.
      technique_id: T1562.001
      data_needed:
        - Security Event Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This activity is significant as it suggests an attacker may have gained access to the domain controller.
  mitigation_plan:
    - priority: immediate
      action: Restrict GPO modification rights on Domain Controllers to a minimal number of Tier-0 administrators.
      owner: IT Operations
      addresses: T1562.001
      evidence: Prevents unauthorized changes to audit policies that lead to this detection.
  gaps:
    - Audit logging needs to be configured at the Domain level to reliably capture these events.
---

This threat brief focuses on the detection of audit policy tampering on Active Directory (AD) Domain Controllers. Attackers who gain administrative access to a Domain Controller (DC) often attempt to disable audit logging to evade detection for further malicious actions, such as credential dumping, lateral movement, or persistence installation. This activity is logged in Windows Security Event Logs via EventCode 4719. Monitoring for the removal of audit policy subcategories is critical, as it serves as a high-fidelity indicator of an adversary attempting to blind security operations. If an attacker succeeds in disabling these policies, they can significantly increase their dwell time and mask their subsequent operational steps, ultimately facilitating full network compromise. Defenders should prioritize alerting on this event, as there are rarely legitimate administrative reasons to disable domain-wide audit subcategories on a production Domain Controller.

## Impact

Successful tampering with audit policies on a Domain Controller prevents security teams from identifying further attacker activity, including privilege escalation and data exfiltration. This visibility gap allows adversaries to maintain persistence within the environment, potentially leading to unauthorized access to sensitive corporate data and full control over the identity infrastructure.

## Recommendation

1. Enable and ingest Windows EventCode 4719 from all Domain Controllers into your SIEM/centralized log management platform.
2. Implement the Sigma rule below to alert on any modification to audit policy success or failure settings.
3. Integrate domain controller assets into your Asset and Identities (A&I) framework to allow for targeted filtering and higher priority alerting when this event occurs on critical infrastructure.
4. Establish an automated incident response playbook that triggers an immediate investigation upon any detection of EventCode 4719, as this event on a DC is rarely benign.
