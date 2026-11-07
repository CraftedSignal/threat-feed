---
brief_id: brief-2026-11-07-ibm-api-connect-bola
event_id: brief-2026-11-07-ibm-api-connect-bola
revision: 1
activity_at: "2026-11-07T06:00:31Z"
title: 'IBM API Connect: Broken Object Level Authorization (CVE-2026-16715)'
slug: 2026-11-ibm-api-connect-bola
description: IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 are vulnerable to a broken object-level authorization flaw that allows authenticated attackers to access data from other tenants.
date: "2026-11-07T06:00:31Z"
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
  validation_status: validated against source
cpes:
  - cpe:2.3:a:ibm:api_connect:*:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - API Connect (10.0.8.0 through 10.0.8.12, 12.1.0.0 through 12.1.1.2)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: This vulnerability allows a remote authenticated attacker to access sensitive information belonging to other tenants within the multi-tenant environment.
    confidence_band: high
cves:
  - id: CVE-2026-16715
    cvss: 7.7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16715
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory IBM API Connect deployments and prepare for version upgrade to address CVE-2026-16715
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2
  hunt_leads:
    - lead: Identify authenticated API requests showing an account identifier accessing resources associated with different Tenant IDs in a single session
      technique_id: T1530
      data_needed:
        - API Connect access/audit logs
        - Gateway transaction logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability results from broken object-level authorization across tenants
---

IBM API Connect contains a broken object-level authorization (BOLA) vulnerability. An authenticated attacker can exploit this flaw to retrieve sensitive information belonging to other tenants in a multi-tenant environment. This issue affects IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2.

## Impact

Successful exploitation allows for unauthorized cross-tenant data access, potentially exposing sensitive API configuration or data protected by the gateway.

## Recommendation

- Identify and inventory all IBM API Connect instances within the environment.
- Review vendor security bulletins for IBM API Connect to identify the specific patch or upgrade path for the affected 10.x and 12.x versions.
- Apply security updates immediately once released by IBM.
- Audit API access logs to identify suspicious patterns of unauthorized object access (e.g., a single authenticated user accessing multiple distinct tenant IDs).
