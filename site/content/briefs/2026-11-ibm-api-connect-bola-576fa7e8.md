---
brief_id: brief-2026-11-07-ibm-api-connect-bola-576fa7e8
event_id: brief-2026-11-07-ibm-api-connect-bola-576fa7e8
revision: 1
activity_at: "2026-11-07T07:52:07Z"
title: 'IBM API Connect: Broken object-level authorization (CVE-2026-17283)'
slug: 2026-11-ibm-api-connect-bola-576fa7e8
description: A broken object-level authorization vulnerability in IBM API Connect allows remote authenticated attackers to access sensitive information by bypassing authorization controls.
date: "2026-11-07T07:52:07Z"
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
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Needs environment validation for API access pattern logging.
cpes:
  - cpe:2.3:a:ibm:api_connect:10.0.8.0:*:*:*:*:*:*:*
  - cpe:2.3:a:ibm:api_connect:12.1.0.0:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - API Connect (10.0.8.0 through 10.0.8.12, 12.1.0.0 through 12.1.1.2)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: This flaw allows a remote authenticated attacker to bypass authorization controls and access sensitive information to which they should not have access.
    confidence_band: high
cves:
  - id: CVE-2026-17283
    cvss: 7.7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17283
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory IBM API Connect instances and monitor for vendor patches.
      owner: IT Operations
      due: 48h
      evidence: Vulnerable versions identified in NVD advisory.
  hunt_leads:
    - lead: Identify authenticated API users requesting sequential or anomalous object IDs.
      technique_id: T1530
      data_needed:
        - API Access Logs
        - Gateway Transaction Logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: BOLA vulnerability permits unauthorized access to sensitive objects by authenticated users.
  mitigation_plan:
    - priority: immediate
      action: Apply security patches for CVE-2026-17283 upon release.
      owner: IT Operations
      addresses: CVE-2026-17283
      evidence: Standard remediation for CVE disclosure.
---

IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 are vulnerable to a broken object-level authorization (BOLA) flaw. This vulnerability enables a remote authenticated attacker to interact with unauthorized objects and retrieve sensitive information. No exploitation details or patch availability dates beyond the advisory notification are disclosed at this time.

## Impact

Successful exploitation allows an authenticated attacker to bypass authorization mechanisms, leading to unauthorized disclosure of sensitive data managed by the API Connect platform.

## Recommendation

- Inventory all deployed instances of IBM API Connect.
- Monitor vendor release channels for the issuance of security patches addressing CVE-2026-17283.
- Review API access logs for anomalous patterns where authenticated users request identifiers outside their standard scope or expected resource patterns.
