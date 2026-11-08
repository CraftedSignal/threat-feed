---
brief_id: brief-2026-11-08-openemr-ssrf
event_id: brief-2026-11-08-openemr-ssrf
revision: 1
activity_at: "2026-11-08T15:34:48Z"
title: 'OpenEMR: Server-side request forgery in OAuth2 client registration (CVE-2026-124466)'
slug: 2026-11-openemr-ssrf
description: OpenEMR versions prior to 8.4.0 contain an SSRF vulnerability in the OAuth2 client registration process that allows unauthenticated attackers to probe internal services and cloud metadata endpoints.
date: "2026-11-08T15:34:48Z"
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
  validation_status: Needs environment validation of OAuth2 registration logs
cpes:
  - cpe:2.3:a:open-emr:openemr:*:*:*:*:*:*:*:*
vendors:
  - OpenEMR
products:
  - OpenEMR (< 8.4.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: OpenEMR before 8.4.0 contains a server-side request forgery vulnerability that allows unauthenticated attackers to make the server send HTTP requests.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Attackers can trigger the fetch ... to probe internal services and reach cloud metadata endpoints.
    confidence_band: high
cves:
  - id: CVE-2026-124466
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124466
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch OpenEMR to version 8.4.0
      owner: IT Operations
      due: 24h
      evidence: Vulnerability fixed in 8.4.0
  hunt_leads:
    - lead: Inspect OAuth2 registration activity for unusual jwks_uri inputs
      technique_id: T1190
      data_needed:
        - Application logs capturing client registration requests and parameters
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers register an OAuth2 client with an unvalidated jwks_uri
  mitigation_plan:
    - priority: immediate
      action: Implement egress filtering on the OpenEMR server to block access to metadata IP 169.254.169.254
      owner: IT Operations
      addresses: CVE-2026-124466
      evidence: Attackers use SSRF to reach cloud metadata endpoints
---

OpenEMR versions before 8.4.0 are susceptible to a server-side request forgery (SSRF) vulnerability. The flaw exists within the OAuth2 client registration mechanism, where an unvalidated `jwks_uri` can be registered. An unauthenticated attacker can subsequently invoke the token introspection endpoint using an unsigned `client_assertion`, forcing the OpenEMR server to initiate HTTP requests to arbitrary destinations. This can be used to perform internal network reconnaissance or access sensitive cloud metadata services.

## Impact

Successful exploitation allows unauthenticated attackers to interact with internal-only services or cloud metadata endpoints (e.g., 169.254.169.254) from the perspective of the vulnerable server, potentially leading to unauthorized data access or credential exfiltration.

## Recommendation

* Upgrade OpenEMR to version 8.4.0 or later immediately.
* Audit OAuth2 client registration logs for suspicious `jwks_uri` entries pointing to unexpected domains or internal IP ranges.
* Restrict the server's egress traffic via network security groups to prevent unauthorized outbound connections to internal service endpoints or cloud metadata services.
