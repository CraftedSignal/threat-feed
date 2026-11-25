---
brief_id: brief-2026-11-25-azure-ad-health-agent-registry-access
event_id: brief-2026-11-25-azure-ad-health-agent-registry-access
revision: 1
activity_at: "2026-11-25T16:21:57Z"
title: Azure AD Health Service Agent registry access monitoring
slug: 2026-11-azure-ad-health-agent-registry-access
description: This brief outlines the detection of unauthorized access to Azure AD Health service agent registry keys which may be used to extract sensitive configuration data for hybrid identity exploitation.
date: "2026-11-25T16:21:57Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
qa_status:
  verdict: pass
tags:
  - identity-security
  - discovery
  - windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1012
    technique_name: Query Registry
    evidence: This detection uses Windows security events to detect suspicious access attempts to the registry key values and sub-keys of Azure AD Health service agents.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/security/win_security_aadhealth_svc_agent_regkey_access.yml
rules:
  - title: Detect Suspicious Access to Azure AD Health Agent Registry Keys
    description: Detects unauthorized access attempts to Azure AD Health service agent registry keys. Requires a SACL set on the key to generate Windows Security events.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1012
    data_sources:
      - registry_set
      - windows
      - security
rules_count: 1
action_plan:
  priority: enrich_before_decision
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable SACL auditing on the registry key HKLM:\SOFTWARE\Microsoft\ADHealthAgent across all servers running AD Connect or AD FS health agents.
      owner: IT Operations
      due: 48h
  hunt_leads:
    - lead: Search for non-standard processes interacting with the ADHealthAgent registry hive in existing audit logs.
      technique_id: T1012
      data_needed:
        - Security Event Log
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Information from AD Health service agents can be used to potentially abuse some of the features provided by those services in the cloud.
---

## Overview

Accessing the registry keys associated with the Azure AD Health service agent (specifically HKLM:\SOFTWARE\Microsoft\ADHealthAgent) allows an attacker to potentially compromise identity-related configurations. In hybrid environments, this data can be misused to abuse features such as Federation, potentially leading to unauthorized token generation or other identity-based attacks. Monitoring requires configuring a System Access Control List (SACL) on the target registry path to capture events in the Windows Security log.

## Recommendation

- Configure a SACL on the registry key HKLM:\SOFTWARE\Microsoft\ADHealthAgent to log object access (Success/Failure).
- Deploy the provided Sigma rule to audit 4656/4663 Event IDs to identify processes interacting with this key that are not part of the legitimate Azure AD Health agent suite.
