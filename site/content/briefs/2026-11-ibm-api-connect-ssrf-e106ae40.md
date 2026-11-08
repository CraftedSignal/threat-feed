---
brief_id: brief-2026-11-08-ibm-api-connect-ssrf-e106ae40
event_id: brief-2026-11-08-ibm-api-connect-ssrf-e106ae40
revision: 1
activity_at: "2026-11-08T06:55:44Z"
title: 'IBM API Connect: Server-side request forgery (CVE-2026-17327)'
slug: 2026-11-ibm-api-connect-ssrf-e106ae40
description: IBM API Connect versions 12.1.0.0 through 12.1.1.2 contain a server-side request forgery (SSRF) vulnerability that allows a remote authenticated attacker to access sensitive information.
date: "2026-11-08T06:55:44Z"
type: threat
types:
  - threat
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
  validation_status: Documentation reviewed; SSRF mitigation strategy defined.
cpes:
  - cpe:2.3:a:ibm:api_connect:12.1.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:ibm:api_connect:12.1.1.2:*:*:*:*:*:*:*
tags:
  - ssrf
  - vulnerability
  - api
vendors:
  - IBM
products:
  - API Connect (12.1.0.0 through 12.1.1.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to obtain sensitive information due to server-side request forgery.
    confidence_band: high
cves:
  - id: CVE-2026-17327
    cvss: 8.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17327
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory IBM API Connect deployments to identify vulnerable versions
      owner: IT Operations
      due: 48h
      evidence: Vulnerability impacts IBM API Connect 12.1.0.0 through 12.1.1.2
  hunt_leads:
    - lead: Identify anomalous outbound network requests originating from the API Connect gateway infrastructure
      technique_id: T1190
      data_needed:
        - Firewall or VPC flow logs for outbound connections from API Connect servers
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: SSRF vulnerability allows the server to make unauthorized requests to internal or external resources
  mitigation_plan:
    - priority: immediate
      action: Apply vendor-supplied patches for CVE-2026-17327 as soon as they become available
      owner: IT Operations
      addresses: CVE-2026-17327
      evidence: IBM API Connect vulnerability
---

IBM API Connect versions 12.1.0.0 through 12.1.1.2 contain a server-side request forgery (SSRF) vulnerability. An authenticated remote attacker can manipulate requests handled by the API gateway to cause the server to perform unauthorized actions or access sensitive resources. As of the current advisory, there are no documented details regarding the specific API endpoints susceptible to this manipulation or public evidence of in-the-wild exploitation.

## Impact

Successful exploitation allows a remote authenticated attacker to perform server-side requests, potentially resulting in the disclosure of sensitive internal information or interaction with protected internal network services.

## Recommendation

- Inventory instances of IBM API Connect within the environment to identify versions 12.1.0.0 through 12.1.1.2.
- Monitor the vendor advisory for patch availability and ensure a maintenance window is scheduled for the remediation of CVE-2026-17327.
- Implement restrictive network egress filtering on the API Connect server to limit internal service access, mitigating the impact of potential SSRF exploitation.
