---
brief_id: brief-2026-11-07-ibm-api-connect-dos
event_id: brief-2026-11-07-ibm-api-connect-dos
revision: 1
activity_at: "2026-11-07T07:51:49Z"
title: 'IBM API Connect: Denial of Service via uncontrolled resource consumption (CVE-2026-17279)'
slug: 2026-11-ibm-api-connect-dos
description: IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 are susceptible to a remote authenticated denial of service attack caused by uncontrolled resource consumption.
date: "2026-11-07T07:51:49Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:ibm:api_connect:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - api-security
  - cloud
vendors:
  - IBM
products:
  - API Connect (10.0.8.0-10.0.8.12, 12.1.0.0-12.1.1.2)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A remote authenticated attacker can trigger uncontrolled resource consumption by sending specifically crafted requests that stall internal processing, leading to service unavailability.
    confidence_band: high
cves:
  - id: CVE-2026-17279
    cvss: 7.7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17279
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory IBM API Connect deployments to identify versions 10.0.8.0-10.0.8.12 and 12.1.0.0-12.1.1.2.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability scope defined by NVD
  hunt_leads:
    - lead: Identify authenticated API requests that result in excessive internal processing time or 5xx server errors.
      technique_id: T1499
      data_needed:
        - API Gateway access logs
        - Application performance monitoring (APM) logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Requests cause internal processing to stall.
  mitigation_plan:
    - priority: immediate
      action: Apply vendor-supplied patches for CVE-2026-17279 upon release.
      owner: IT Operations
      addresses: CVE-2026-17279
      evidence: Vendor security advisory remediation
---

IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 contain a vulnerability that permits an authenticated remote attacker to perform a denial of service attack. By sending specially crafted requests, an attacker can trigger uncontrolled resource consumption within the system, resulting in stalled internal processing and service unavailability.

## Impact
Successful exploitation results in service unavailability, preventing legitimate users from accessing API Connect services. The vulnerability carries a CVSS v3.1 base score of 7.7.

## Recommendation
Inventory all instances of IBM API Connect within the environment and verify version numbers against the affected ranges. Monitor vendor security updates and apply patches as they become available to remediate CVE-2026-17279.
