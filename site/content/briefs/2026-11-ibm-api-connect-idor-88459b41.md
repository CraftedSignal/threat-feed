---
brief_id: brief-2026-11-07-ibm-api-connect-idor-88459b41
event_id: brief-2026-11-07-ibm-api-connect-idor-88459b41
revision: 1
activity_at: "2026-11-07T06:08:22Z"
title: 'IBM API Connect: Insecure direct object reference (CVE-2026-17320)'
slug: 2026-11-ibm-api-connect-idor-88459b41
description: IBM API Connect versions 12.1.0.0 through 12.1.1.2 are vulnerable to an Insecure Direct Object Reference (IDOR) flaw, allowing a remote authenticated attacker to access sensitive information.
date: "2026-11-07T06:08:22Z"
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
cpes:
  - cpe:2.3:a:ibm:api_connect:12.1.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:ibm:api_connect:12.1.1.2:*:*:*:*:*:*:*
tags:
  - idor
  - vulnerability
  - api-security
vendors:
  - IBM
products:
  - API Connect (12.1.0.0 through 12.1.1.2)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to obtain sensitive information due to an insecure direct object reference.
    confidence_band: high
cves:
  - id: CVE-2026-17320
    cvss: 7.7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17320
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory IBM API Connect deployments to identify vulnerable versions.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-17320 affects version range 12.1.0.0-12.1.1.2.
  hunt_leads:
    - lead: Identify authenticated API requests indicating IDOR-style resource enumeration
      technique_id: T1592
      data_needed:
        - API Access Logs
        - HTTP status codes
        - Request parameters / URI structure
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability involves insecure direct object references allowing access to sensitive data.
  mitigation_plan:
    - priority: immediate
      action: Monitor IBM Security Advisories for patch release.
      owner: IT Operations
      addresses: CVE-2026-17320
      evidence: NVD disclosure of CVE-2026-17320.
---

IBM API Connect versions 12.1.0.0 through 12.1.1.2 contain an Insecure Direct Object Reference (IDOR) vulnerability identified as CVE-2026-17320. This vulnerability allows a remote authenticated attacker to access sensitive information by manipulating direct object references within the application. No patch availability or remediation steps are explicitly detailed in the current NVD advisory.

## Impact
Successful exploitation allows a remote authenticated attacker to bypass authorization controls and retrieve sensitive information, leading to unauthorized data exposure.

## Recommendation
- Inventory all instances of IBM API Connect within the environment to identify systems running versions 12.1.0.0 through 12.1.1.2.
- Monitor vendor security portals for the release of security patches or configuration guidance to mitigate CVE-2026-17320.
- Audit API access logs for anomalous patterns where authenticated users request resources outside their typical scope or ID ranges.
