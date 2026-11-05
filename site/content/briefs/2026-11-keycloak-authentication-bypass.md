---
brief_id: brief-2026-11-05-keycloak-authentication-bypass
event_id: brief-2026-11-05-keycloak-authentication-bypass
revision: 1
activity_at: "2026-11-05T18:23:04Z"
title: 'Keycloak: Authentication bypass in Organization identity-first login flow (CVE-2026-112208)'
slug: 2026-11-keycloak-authentication-bypass
description: A vulnerability in the Keycloak identity-first login flow allows an authenticated attacker belonging to multiple organizations to bypass authentication and perform a full account takeover of a victim.
date: "2026-11-05T18:23:04Z"
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
  validation_status: Needs environment validation
cpes:
  - cpe:2.3:a:keycloak:keycloak:*:*:*:*:*:*:*:*
tags:
  - cve-2026-112208
  - authentication-bypass
  - identity-access-management
vendors:
  - Keycloak
products:
  - Keycloak
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: An attacker can then provide a victim's username, and the system incorrectly treats the stale flag as proof of the victim's identity.
    confidence_band: high
cves:
  - id: CVE-2026-112208
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112208
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Inventory all deployed Keycloak instances to prepare for patching
      owner: IT Operations
      due: 24h
      evidence: Vulnerability in Keycloak authentication server
  hunt_leads:
    - lead: Identify abnormal user activity involving rapid switches between authentication, registration, and password reset endpoints
      technique_id: T1550
      data_needed:
        - Keycloak server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The issue occurs when an attacker... initiates a login and then switches to a registration or password reset path.
  mitigation_plan:
    - priority: immediate
      action: Apply security patches for CVE-2026-112208 as soon as provided by the vendor
      owner: IT Operations
      addresses: CVE-2026-112208
      evidence: High severity authentication bypass
---

A flaw exists in the Organization identity-first login flow of the Keycloak authentication server (CVE-2026-112208). An attacker who is a member of multiple organizations can trigger a state machine failure by initiating a login and subsequently switching to a registration or password reset flow. The application fails to clear a session flag representing a successful login, allowing the attacker to authenticate as a different user by providing that user's identifier. The server incorrectly treats the stale, pre-existing session flag as proof of the victim's identity.

## Impact

An attacker can bypass authentication to gain full unauthorized access to a victim's account and all associated applications integrated with the compromised Keycloak instance.

## Recommendation

* Inventory all internet-facing Keycloak instances.
* Monitor vendor security advisories for the release of a patch addressing CVE-2026-112208.
* Implement strict monitoring for login flow anomalies where users frequently switch between authentication, registration, and password reset contexts.
