---
brief_id: brief-2026-11-20-entra-id-user-lifecycle-anomaly
event_id: brief-2026-11-20-entra-id-user-lifecycle-anomaly
revision: 1
activity_at: "2026-11-20T14:00:18Z"
title: Entra ID User Created or Deleted by Unusual UPN
slug: 2026-11-entra-id-user-lifecycle-anomaly
description: This rule monitors for the first-time use of administrative user principals to create or delete Entra ID accounts within a 10-day lookback window, which may indicate persistence or impact activity by an adversary.
date: "2026-11-20T14:00:18Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
tags:
  - 'Domain: Cloud'
  - 'Data Source: Azure'
  - 'Data Source: Microsoft Entra ID Audit Logs'
  - 'Domain: Identity'
  - 'Platform: Azure'
  - 'Platform: Entra ID'
  - 'Tactic: Persistence'
  - 'Tactic: Impact'
  - 'Rule Type: New Terms'
products:
  - Microsoft Entra ID
affected_os:
  - Azure
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    subtechnique_id: T1136.003
    subtechnique_name: Cloud Account
    evidence: Adversaries with compromised privileged identities create users for persistence or delete users for impact.
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1531
    technique_name: Account Access Removal
    evidence: Adversaries with compromised privileged identities create users for persistence or delete users for impact.
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/persistence_entra_user_created_or_deleted_by_unusual_upn.toml
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.003/T1136.003.md
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1531/T1531.md
rules:
  - title: Entra ID User Created or Deleted by Unusual UPN
    description: Identifies the first time a user-initiated principal creates or deletes an Entra ID user, potentially indicating an adversary with a compromised privileged identity.
    platform: sigma
    severity: low
    tactics:
      - impact
      - persistence
    data_sources:
      - audit_log
      - azure
rules_count: 1
---

## Overview
The Elastic detection rule identifies anomalous user lifecycle events within Microsoft Entra ID by flagging the first time a user-initiated principal creates or deletes a user ('Add user' or 'Delete user') within a 10-day history window. The rule excludes app/service-initiated lifecycle events such as HR or SCIM provisioning.

## Attack Chain
Adversaries with compromised privileged identities may create users to establish persistence or delete users to cause impact or evade detection.

## Impact
The creation of unauthorized directory users provides persistence via backdoor accounts, while the deletion of existing users results in service disruption and potential evasion.

## Recommendation
- Verify whether the initiating principal (`azure.auditlogs.properties.initiated_by.user.userPrincipalName`) is authorized to perform user lifecycle management.
- Investigate the target user (`azure.auditlogs.properties.target_resources.0.user_principal_name`) for unauthorized modifications.
- Correlate events with role assignments, credential additions, or sign-ins involving the target account.
- In confirmed unauthorized cases, disable or remove created accounts, restore deleted accounts, review follow-on activity, and rotate the initiator's credentials.
