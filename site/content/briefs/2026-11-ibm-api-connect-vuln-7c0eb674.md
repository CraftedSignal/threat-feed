---
brief_id: brief-2026-11-07-ibm-api-connect-vuln-7c0eb674
event_id: brief-2026-11-07-ibm-api-connect-vuln-7c0eb674
revision: 1
activity_at: "2026-11-07T06:05:55Z"
title: 'IBM API Connect: Information disclosure via external references (CVE-2026-17285)'
slug: 2026-11-ibm-api-connect-vuln-7c0eb674
description: IBM API Connect contains a vulnerability that allows a remote authenticated attacker to perform unauthorized data retrieval through improper validation of external references during schema validation.
date: "2026-11-07T06:05:55Z"
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
  - cpe:2.3:a:ibm:api_connect:*:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - API Connect (10.0.8.0-10.0.8.12, 12.1.0.0-12.1.1.2)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: When schemas are validated, references to external resources are not sufficiently restricted, which could allow the server to retrieve content it should not access.
    confidence_band: high
cves:
  - id: CVE-2026-17285
    cvss: 7.7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17285
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory IBM API Connect deployments for affected versions
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-17285 affects specified version ranges in API Connect
  hunt_leads:
    - lead: Outbound network connections from API Connect servers to internal or unexpected external addresses
      technique_id: T1592
      data_needed:
        - Firewall or VPC flow logs
        - Proxy access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The server retrieves content it should not access via external references
---

IBM API Connect versions 10.0.8.0 through 10.0.8.12 and 12.1.0.0 through 12.1.1.2 contain a vulnerability (CVE-2026-17285) that permits an authenticated remote attacker to obtain sensitive information. The flaw stems from improper validation of external references when the application processes schemas, allowing the server to fetch content from unauthorized external resources.

## Impact

Successful exploitation allows a remote authenticated attacker to access and retrieve sensitive information from external resources that the server should not have permission to reach.

## Recommendation

- Inventory instances of IBM API Connect within your environment to identify versions 10.0.8.0-10.0.8.12 and 12.1.0.0-12.1.1.2.
- Review vendor security bulletins for the release of patches addressing CVE-2026-17285 and schedule upgrades immediately upon availability.
- Review API gateway configuration logs for abnormal outbound requests originating from the API Connect server towards internal or external unauthorized endpoints.
