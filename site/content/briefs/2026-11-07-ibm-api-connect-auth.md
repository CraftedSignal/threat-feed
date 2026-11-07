---
brief_id: brief-2026-11-07-ibm-api-connect-auth
event_id: brief-2026-11-07-ibm-api-connect-auth
revision: 1
activity_at: "2026-11-07T05:50:01Z"
title: 'IBM API Connect: Insecure tenant authorization (CVE-2026-17066)'
slug: 2026-11-07-ibm-api-connect-auth
description: IBM API Connect versions 12.1.0.0 through 12.1.1.2 contain a broken access control vulnerability that allows a remote authenticated attacker to access, modify, or delete data across tenants.
date: "2026-11-07T05:50:01Z"
type: advisory
types:
  - advisory
severities:
  - critical
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
  - cpe:2.3:a:ibm:api_connect:12.1.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:ibm:api_connect:12.1.1.2:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - API Connect (12.1.0.0-12.1.1.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A remote authenticated attacker can leverage this flaw to perform unauthorized actions, including the access, modification, or deletion of data belonging to other tenants.
    confidence_band: high
cves:
  - id: CVE-2026-17066
    cvss: 9.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17066
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory IBM API Connect versions across the environment.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-17066 affects versions 12.1.0.0 through 12.1.1.2.
  hunt_leads:
    - lead: Monitor application audit logs for cross-tenant API requests or resource access attempts by authenticated users.
      technique_id: T1068
      data_needed:
        - IBM API Connect application audit logs
        - Tenant ID or resource context fields in API logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attacker leverages flaw to perform unauthorized actions on data belonging to other tenants.
  mitigation_plan:
    - priority: immediate
      action: Apply vendor-supplied patches as soon as they become available.
      owner: IT Operations
      addresses: CVE-2026-17066
      evidence: NVD advisory confirms vulnerability in specified version range.
---

CVE-2026-17066 identifies a critical broken access control vulnerability in IBM API Connect versions 12.1.0.0 through 12.1.1.2. The flaw allows a remote authenticated attacker to bypass authorization checks within a multi-tenant environment. Successful exploitation grants the attacker the ability to view, modify, or delete sensitive information belonging to other tenants. No patch availability is specified in the NVD notice; administrators should monitor vendor security portals for immediate updates.

## Impact

Successful exploitation allows for unauthorized information disclosure, data manipulation, and data destruction across tenant boundaries. This represents a complete compromise of tenant isolation for affected installations.

## Recommendation

* Inventory all IBM API Connect deployments to identify instances running versions 12.1.0.0 through 12.1.1.2.
* Restrict administrative and tenant-level access to the API Connect management console until a vendor-supplied patch is applied.
* Audit tenant activity logs for anomalous cross-tenant data access patterns or unauthorized modification attempts.
* Review vendor-provided security bulletins for the release of fixed versions of IBM API Connect.
