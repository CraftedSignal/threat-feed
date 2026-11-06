---
brief_id: brief-2026-11-06-keycloak-identity-resolution-bypass
event_id: brief-2026-11-06-keycloak-identity-resolution-bypass
revision: 1
activity_at: "2026-11-06T00:35:30Z"
title: 'Keycloak: Authorization bypass via hardcoded-claim mapper manipulation (CVE-2026-97847)'
slug: 2026-11-keycloak-identity-resolution-bypass
description: A vulnerability in Keycloak’s protocol mapper and identity resolution components allows an attacker with limited client management permissions to escalate privileges to realm administrator by manipulating identity claims in sessionless service-account tokens.
date: "2026-11-06T00:35:30Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: needs_environment_validation
cpes:
  - cpe:2.3:a:redhat:keycloak:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - auth-bypass
  - keycloak
vendors:
  - Red Hat
products:
  - Keycloak
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    subtechnique_id: T1078.004
    subtechnique_name: Cloud Accounts
    evidence: By utilizing hardcoded-claim mappers to override identity claims within sessionless service-account tokens, an attacker can cause the system to misidentify the bearer as a highly privileged user.
    confidence_band: high
cves:
  - id: CVE-2026-97847
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-97847
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Identify Keycloak instances and audit client configurations for hardcoded-claim mappers
      owner: Security Operations
      due: 48h
      evidence: Vulnerability requires specific configuration of hardcoded-claim mappers
  hunt_leads:
    - lead: Hunt for unusual administrative changes or unauthorized role modifications originating from service accounts
      technique_id: T1078.004
      data_needed:
        - Keycloak audit logs
        - Identity provider administrative action logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation results in full control over the realm via privilege escalation
  mitigation_plan:
    - priority: immediate
      action: Apply security patches for CVE-2026-97847
      owner: IT Operations
      addresses: CVE-2026-97847
      evidence: Patching is the primary remediation for this software vulnerability
---

A security flaw exists in Keycloak concerning its protocol mapper and identity resolution logic. An attacker who possesses limited client management permissions can configure hardcoded-claim mappers to override identity claims within sessionless service-account tokens. Because these tokens do not contain a session ID, Keycloak fails to validate the claim integrity against an active session, leading to the misidentification of the token bearer as a highly privileged user, such as a realm administrator. This allows the attacker to obtain full control over the target realm.

## Impact
Successful exploitation allows a low-privileged user with client management rights to escalate privileges to a realm administrator. This grants the attacker full control over the impacted realm, including user management, configuration changes, and access to all protected resources within that realm.

## Recommendation
- Inventory all Keycloak instances within the environment.
- Review current client configurations, specifically looking for anomalous usage of hardcoded-claim mappers within service-account token requests.
- Apply security patches for CVE-2026-97847 as soon as they are made available by Red Hat.
- Audit administrative role assignments and service account permissions to ensure the principle of least privilege is maintained for client managers.
