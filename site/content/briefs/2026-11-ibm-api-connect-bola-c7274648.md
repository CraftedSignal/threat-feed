---
brief_id: brief-2026-11-07-ibm-api-connect-bola-c7274648
event_id: brief-2026-11-07-ibm-api-connect-bola-c7274648
revision: 1
activity_at: "2026-11-07T06:06:43Z"
title: 'IBM API Connect: Broken Object Level Authorization (CVE-2026-17293)'
slug: 2026-11-ibm-api-connect-bola-c7274648
description: IBM API Connect versions 10.0.8.0-10.0.8.12 and 12.1.0.0-12.1.1.2 contain a Broken Object Level Authorization flaw allowing remote authenticated attackers to modify arbitrary user profile data.
date: "2026-11-07T06:06:43Z"
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
  - cpe:2.3:a:ibm:api_connect:10.0.8.0:*:*:*:*:*:*:*
  - cpe:2.3:a:ibm:api_connect:12.1.0.0:*:*:*:*:*:*:*
tags:
  - api-security
  - broken-object-level-authorization
  - bola
  - web-application
vendors:
  - IBM
products:
  - API Connect (10.0.8.0 through 10.0.8.12, 12.1.0.0 through 12.1.1.2)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: A remote authenticated attacker can exploit this weakness to modify user profile information because the application fails to verify if the requesting user has the appropriate authorization to perform modifications on the targeted object.
    confidence_band: high
cves:
  - id: CVE-2026-17293
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17293
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Inventory IBM API Connect deployments and compare against vulnerable version ranges.
      owner: IT Operations
      due: 24h
      evidence: Vulnerable version ranges defined in CVE-2026-17293.
  hunt_leads:
    - lead: Identify abnormal frequency or target variance in user profile update API requests from authenticated accounts.
      technique_id: T1548
      data_needed:
        - API access logs
        - User authentication context
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows modification of user profile info via BOLA.
---

IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 are susceptible to a Broken Object Level Authorization (BOLA) vulnerability, tracked as CVE-2026-17293. The vulnerability exists because the application fails to perform adequate authorization checks when processing requests to modify user profile information. A remote authenticated attacker can manipulate API calls to target and alter profiles belonging to other users.

## Impact

Successful exploitation allows a remote authenticated attacker to modify user profile data without proper authorization.

## Recommendation

- Audit internal API logs to identify any unauthorized attempts to access or modify user profile objects.
- Review IBM security bulletins for official patches or configuration mitigations.
- Apply the vendor-provided security updates to IBM API Connect immediately upon availability.
