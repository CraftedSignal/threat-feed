---
title: Anthropic Organization Member and Group Enumeration Reconnaissance
slug: 2026-10-anthropic-recon
description: Adversaries are performing reconnaissance within Anthropic organizations by chaining user and group enumeration actions, signaling intent for account takeover or unauthorized data access.
date: "2026-10-01T20:09:17Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - GenAI
  - Discovery
  - Cloud
  - UEBA
vendors:
  - Anthropic
products:
  - Anthropic (Audit Logs)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Permission Groups Discovery
    evidence: Chaining these read actions maps membership and group structure and commonly precedes targeted role grants, invites, or data collection against high-value accounts.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: 'Detects a single user performing at least two distinct organization discovery actions within a 10-minute window: listing users, exporting members, or viewing groups.'
    confidence_band: high
references:
  - https://platform.claude.com/docs/en/api/compliance/activities/list
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/anthropic/discovery_anthropic_organization_member_group_enumeration.toml
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection logic to monitor for multiple discovery actions by non-admin users
      owner: Detection Engineering
      due: 48h
      evidence: Source detection rule requirement
  enrichment_needed:
    - item: Source IP and User Agent patterns
      owner: SOC
      reason: To differentiate automated reconnaissance from legitimate interactive admin sessions
      evidence: Source investigation guide
  hunt_leads:
    - lead: Identify users performing more than two unique discovery actions in a 10-minute window
      technique_id: T1087.004
      data_needed:
        - Anthropic Audit Logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source rule query definition
  mitigation_plan:
    - priority: medium_term
      action: Restrict member export and group view permissions to verified IAM administrators
      owner: IT Operations
      addresses: T1069.003
      evidence: Source triage guide
---

This threat brief focuses on discovery activities observed within Anthropic organization audit logs. Threat actors are utilizing legitimate platform API actions to map the organizational structure of a tenant. By chaining multiple distinct read operations - specifically listing users, exporting member lists, and viewing group configurations - attackers gain visibility into internal teams, role structures, and high-value accounts. This reconnaissance phase typically precedes malicious activity such as privilege escalation, unauthorized role grants, or targeted data exfiltration. Because these actions leverage standard identity and access management (IAM) functionality, defenders must distinguish between legitimate administrative audits and unauthorized discovery by non-administrative users.

## Impact

Successful reconnaissance allows an adversary to identify and target high-privilege accounts for takeover, facilitate unauthorized role grants, or perform targeted data collection. This activity poses a significant risk to organizational confidentiality and identity integrity, especially if the account is later used to modify SSO settings, invite malicious external actors, or exfiltrate enterprise-grade GenAI configurations.

## Recommendation

- Implement monitoring for the chaining of organizational discovery actions as outlined in the detection logic below.
- Review and tighten least-privilege policies regarding identity read actions and member exports for non-administrative user roles.
- Audit recent role grants, team invites, and SSO configuration changes when this discovery pattern is identified.
- Validate identified activity against known IT service tickets or scheduled compliance audits to reduce false positives.
