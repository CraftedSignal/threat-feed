---
brief_id: brief-2026-11-07-ibm-api-connect-bola-611f9275
event_id: brief-2026-11-07-ibm-api-connect-bola-611f9275
revision: 1
activity_at: "2026-11-07T06:01:59Z"
title: 'IBM API Connect: Broken Object-Level Authorization (CVE-2026-17112)'
slug: 2026-11-ibm-api-connect-bola-611f9275
description: IBM API Connect versions 10.0.8.0-10.0.8.12 and 12.1.0.0-12.1.1.2 contain a broken object-level authorization (BOLA) vulnerability allowing authenticated attackers to access sensitive data of other tenants.
date: "2026-11-07T06:01:59Z"
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
  validation_status: Needs environment validation of IBM API Connect versioning.
cpes:
  - cpe:2.3:a:ibm:api_connect:10.0.8.0:*:*:*:*:*:*:*
  - cpe:2.3:a:ibm:api_connect:12.1.0.0:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - API Connect (10.0.8.0-10.0.8.12, 12.1.0.0-12.1.1.2)
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: This allows a remote authenticated attacker to access sensitive information belonging to other tenants within the multi-tenant API environment.
    confidence_band: high
cves:
  - id: CVE-2026-17112
    cvss: 7.7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17112
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Identify and patch vulnerable IBM API Connect instances
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-17112 identification
  hunt_leads:
    - lead: Monitor API access logs for anomalous cross-tenant resource requests
      technique_id: T1530
      data_needed:
        - API gateway access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: BOLA vulnerabilities often manifest as unauthorized IDOR patterns in API requests
  mitigation_plan:
    - priority: immediate
      action: Apply vendor-supplied patches for affected versions
      owner: IT Operations
      addresses: CVE-2026-17112
      evidence: NVD disclosure
---

IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 are susceptible to a broken object-level authorization (BOLA) vulnerability. An authenticated attacker can exploit this flaw to bypass tenant isolation and access sensitive data belonging to other tenants within the multi-tenant API environment.

## Impact

Successful exploitation allows a remote authenticated attacker to read sensitive information belonging to other tenants, leading to unauthorized data exposure.

## Recommendation

Identify and inventory instances of IBM API Connect within the environment. Review vendor security bulletins for available patches for the affected versions (10.0.8.0-10.0.8.12 and 12.1.0.0-12.1.1.2) and apply updates immediately.
