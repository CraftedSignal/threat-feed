---
title: Unauthorized Deletion of Anthropic Organization IP Restrictions
slug: 2026-10-anthropic-ip-restriction-deletion
description: An attacker or compromised administrator may delete organization-level IP restrictions in Anthropic to disable network-based access controls and enable the use of administrative credentials from unauthorized locations.
date: "2026-10-01T20:09:08Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - GenAI
  - Anthropic
  - Cloud
  - Defense Evasion
vendors:
  - Anthropic
products:
  - Anthropic API
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: The rule description identifies the deletion of IP restrictions as a defense evasion tactic to widen the allowed surface area.
    confidence_band: high
references:
  - https://platform.claude.com/docs/en/api/compliance/activities/list
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/anthropic/defense_evasion_anthropic_organization_ip_restriction_deleted.toml
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Establish alerting on org_ip_restriction_deleted audit events
      owner: Detection Engineering
      due: 24h
      evidence: Source provides specific logic for event identification
  hunt_leads:
    - lead: Search for org_ip_restriction_deleted events without preceding or following restriction creation/update events
      technique_id: T1562.007
      data_needed:
        - Anthropic Audit Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source notes that unauthorized deletions often lack paired replacement events
  mitigation_plan:
    - priority: immediate
      action: Review all existing organization IP restrictions for accuracy and coverage
      owner: IT Operations
      addresses: Organization network perimeter
      evidence: Source identifies restriction deletion as a primary evasion tactic
---

The deletion of IP restrictions within the Anthropic platform is a critical defense evasion tactic. Organization-level IP restrictions serve as a security boundary, limiting where administrative console sessions and API keys can be utilized. An adversary who gains access to an administrative account can delete these restrictions to remove network-based barriers. This action effectively widens the attack surface, allowing the attacker to interact with the environment from arbitrary network locations without triggering IP-based geofencing or allowlist violations. Because the audit event often fails to capture the specific CIDR block being removed, this activity is an important early indicator of potential unauthorized access. Defenders should treat this as a high-priority alert that warrants an immediate audit of the surrounding administrative activity to ensure that the change was authorized and that no secondary malicious actions - such as new admin key creation or data exports - have occurred.

## Attack Chain

1. Initial access to an administrative session or high-privileged API key via phishing, credential harvesting, or session hijacking.
2. The actor authenticates to the Anthropic platform using the compromised credentials.
3. The actor navigates to the organization configuration settings to identify active network security controls.
4. The actor executes the 'org_ip_restriction_deleted' action to disable the IP-based access limitations.
5. The security control is removed, allowing the actor to establish a C2 or interactive session from an attacker-controlled infrastructure IP.
6. The actor performs follow-on malicious activity, such as creating additional long-lived admin API keys for persistence.
7. The actor exfiltrates sensitive model data or organization information through the now-unrestricted API.

## Impact

Successful exploitation of this technique permits an adversary to bypass organizational perimeter defenses. This can lead to unauthorized data access, the establishment of persistent administrative backdoors, and the potential exfiltration of proprietary model data or organization configuration. If left unmonitored, the removal of these controls grants an attacker the ability to maintain long-term, stealthy access to the organization's administrative infrastructure.

## Recommendation

Prioritize the investigation of any 'org_ip_restriction_deleted' event to determine if it aligns with planned infrastructure maintenance.

- Implement monitoring for the 'org_ip_restriction_deleted' event in your audit logs and escalate any occurrences not linked to a verified change management ticket.
- Pivot to review 'org_ip_restriction_created' or 'org_ip_restriction_updated' events within the same time window to determine if the restriction was simply replaced or entirely removed.
- Audit administrative activity for any anomalies, including logins from non-corporate IP addresses or user agents following the restriction change.
- Consider rotating administrative API keys and resetting sessions if the deletion is confirmed to be unauthorized.
