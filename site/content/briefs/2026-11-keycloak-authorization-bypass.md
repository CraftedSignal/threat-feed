---
brief_id: brief-2026-11-05-keycloak-authorization-bypass
event_id: brief-2026-11-05-keycloak-authorization-bypass
revision: 1
activity_at: "2026-11-05T18:23:09Z"
title: 'Keycloak: UMA Protection API authorization bypass (CVE-2026-114232)'
slug: 2026-11-keycloak-authorization-bypass
description: An authorization bypass vulnerability in the Keycloak UserManagedPermissionService allows authenticated attackers to create policies for resources owned by other users due to insufficient validation of the resourceType field.
date: "2026-11-05T18:23:09Z"
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
cpes:
  - cpe:2.3:a:keycloak:keycloak:*:*:*:*:*:*:*:*
tags:
  - cve-2026-114232
  - authorization-bypass
  - keycloak
  - web-application
vendors:
  - Keycloak
products:
  - Keycloak
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This allows an attacker to create a policy that applies to resources owned by other users, potentially leading to unauthorized access or modification of sensitive data across the entire realm.
    confidence_band: high
cves:
  - id: CVE-2026-114232
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114232
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit Keycloak realm configurations and logs for unauthorized policy creation attempts targeting cross-user resources
      owner: SOC
      due: 48h
      evidence: Vulnerability allows users to create policies for resources owned by others
  hunt_leads:
    - lead: Identify unusual spikes in API requests to the UMA Protection endpoint
      technique_id: T1068
      data_needed:
        - Keycloak server access logs
        - Authorization audit logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The UMA Protection API manages user permissions and is the site of the policy creation logic flaw
  mitigation_plan:
    - priority: immediate
      action: Monitor Keycloak vendor security portal for the patch release addressing CVE-2026-114232
      owner: IT Operations
      addresses: CVE-2026-114232
      evidence: Vendor patch required to remediate logic flaw in UserManagedPermissionService
---

A security flaw (CVE-2026-114232) exists in the UserManagedPermissionService component of the Keycloak authorization server. The UMA Protection API fails to validate the 'resourceType' field when processing policy creation requests. This oversight allows an authenticated user to create policies targeting resources they do not own, potentially enabling unauthorized access to or modification of sensitive data within the same realm.

## Impact
The vulnerability allows authenticated users to escalate privileges by manipulating access control policies. This could lead to unauthorized access to, or modification of, resources managed by other users within the Keycloak environment.

## Recommendation
- Inventory all Keycloak instances within the organization to identify versions utilizing the vulnerable UserManagedPermissionService.
- Monitor the Keycloak authorization server logs for unusual API call patterns related to UMA policy creation.
- Prioritize the application of vendor-supplied patches as soon as they become available to address this authorization logic flaw.
