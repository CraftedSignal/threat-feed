---
brief_id: brief-2026-11-07-ibm-api-connect-traversal
event_id: brief-2026-11-07-ibm-api-connect-traversal
revision: 1
activity_at: "2026-11-07T05:54:39Z"
title: 'IBM API Connect: Path traversal vulnerability (CVE-2026-17339)'
slug: 2026-11-ibm-api-connect-traversal
description: IBM API Connect versions 12.1.0.0 through 12.1.1.2 contain a path traversal vulnerability that permits a remote authenticated attacker to perform unauthorized access or deletion of resources belonging to other tenants.
date: "2026-11-07T05:54:39Z"
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
  validation_status: needs_environment_validation
cpes:
  - cpe:2.3:a:ibm:api_connect:12.1.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:ibm:api_connect:12.1.1.2:*:*:*:*:*:*:*
tags:
  - path-traversal
  - web-application
  - api-security
vendors:
  - IBM
products:
  - API Connect (12.1.0.0 through 12.1.1.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to access or delete resources belonging to other tenants due to path traversal.
    confidence_band: high
cves:
  - id: CVE-2026-17339
    cvss: 9.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17339
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory IBM API Connect deployments to identify vulnerable versions 12.1.0.0-12.1.1.2.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects IBM API Connect 12.1.0.0 through 12.1.1.2.
  hunt_leads:
    - lead: Monitor API gateway access logs for path traversal patterns (e.g., ../, ..%2f) targeting resource identifiers.
      technique_id: T1190
      data_needed:
        - Web server or API gateway access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability is documented as path traversal.
  mitigation_plan:
    - priority: immediate
      action: Apply vendor patches for CVE-2026-17339 as soon as they become available.
      owner: IT Operations
      addresses: CVE-2026-17339
      evidence: IBM API Connect 12.1.0.0 through 12.1.1.2 are affected.
---

IBM API Connect versions 12.1.0.0 through 12.1.1.2 are susceptible to a path traversal vulnerability. This flaw allows a remote, authenticated attacker to manipulate API requests to access or delete resources belonging to other tenants within the multi-tenant environment.

## Impact

Successful exploitation allows for unauthorized cross-tenant data access and the potential destruction of sensitive API resources, leading to a loss of data confidentiality and integrity.

## Recommendation

* Inventory all deployments of IBM API Connect to identify instances running versions 12.1.0.0 through 12.1.1.2.
* Monitor vendor channels for the release of security patches or configuration workarounds for CVE-2026-17339.
* Implement strict request validation and object-level authorization checks at the API gateway layer for all tenant-specific endpoints until updates are applied.
