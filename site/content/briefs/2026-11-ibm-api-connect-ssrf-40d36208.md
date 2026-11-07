---
brief_id: brief-2026-11-07-ibm-api-connect-ssrf-40d36208
event_id: brief-2026-11-07-ibm-api-connect-ssrf-40d36208
revision: 1
activity_at: "2026-11-07T06:02:38Z"
title: 'IBM API Connect: Server-side request forgery (CVE-2026-17188)'
slug: 2026-11-ibm-api-connect-ssrf-40d36208
description: IBM API Connect versions 12.1.0.0 through 12.1.1.2 are vulnerable to server-side request forgery (SSRF) during the import of service definitions, allowing an authenticated attacker to access unauthorized internal resources.
date: "2026-11-07T06:02:38Z"
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
  validation_status: Needs environment validation of API gateway egress traffic logs.
cpes:
  - cpe:2.3:a:ibm:api_connect:12.1.0.0:*:*:*:*:*:*:*
  - cpe:2.3:a:ibm:api_connect:12.1.1.2:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - API Connect (12.1.0.0-12.1.1.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: IBM API Connect 12.1.0.0 through 12.1.1.2 could allow a remote authenticated attacker to obtain sensitive information due to server-side request forgery.
    confidence_band: high
cves:
  - id: CVE-2026-17188
    cvss: 8.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17188
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Identify and patch IBM API Connect versions 12.1.0.0 through 12.1.1.2.
      owner: IT Operations
      due: 72h
      evidence: Vulnerability CVE-2026-17188 affects IBM API Connect 12.1.0.0 through 12.1.1.2.
  hunt_leads:
    - lead: Monitor outbound network traffic from API Connect servers for requests to internal RFC1918 addresses.
      technique_id: T1190
      data_needed:
        - Egress firewall logs
        - Proxy logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability allows the server to be made to request resources it should not access.
  mitigation_plan:
    - priority: immediate
      action: Upgrade IBM API Connect to a patched version beyond 12.1.1.2.
      owner: IT Operations
      addresses: CVE-2026-17188
      evidence: Patching removes the SSRF vulnerability in the service definition import flow.
---

IBM API Connect versions 12.1.0.0 through 12.1.1.2 contain a server-side request forgery (SSRF) vulnerability. An authenticated attacker can exploit this flaw by providing malicious references to external resources during the service definition import process. Successful exploitation allows the server to make requests to internal or restricted network resources, potentially leading to information disclosure.

## Impact
An authenticated attacker can abuse the API import feature to perform reconnaissance on internal network infrastructure or access unauthorized services that are otherwise unreachable from the internet.

## Recommendation
- Inventory all instances of IBM API Connect and identify those running versions 12.1.0.0 through 12.1.1.2.
- Monitor API gateway logs for unusual outbound requests originating from the API Connect server, particularly those targeting internal IP ranges or sensitive internal management interfaces.
- Apply the latest vendor security patches provided by IBM for API Connect to remediate CVE-2026-17188.
