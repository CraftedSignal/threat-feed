---
title: SSRF Vulnerability in NASA earthdata-search
slug: 2026-08-nasa-ssrf
description: NASA earthdata-search version 1.0.0 contains a Server-Side Request Forgery (SSRF) vulnerability in the scaleImage function, allowing remote attackers to perform unauthorized requests.
date: "2026-08-31T15:58:28Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:nasa:earthdata-search:1.0.0:*:*:*:*:*:*:*
vendors:
  - NASA
products:
  - earthdata-search (1.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Performing a manipulation results in server-side request forgery.
    confidence_band: high
cves:
  - id: CVE-2026-82801
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82801
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all internet-facing NASA earthdata-search deployments.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-82801
  mitigation_plan:
    - priority: immediate
      action: Implement egress filtering on servers running earthdata-search to restrict outbound connections to known-necessary endpoints.
      owner: IT Operations
      addresses: CVE-2026-82801
      evidence: Remediation strategy for SSRF vulnerabilities.
---

NASA earthdata-search version 1.0.0 contains a Server-Side Request Forgery (SSRF) vulnerability. The flaw exists within the scaleImage function located in the file serverless/src/scaleImage/handler.js, which is part of the application's scale Endpoint component. This vulnerability allows an unauthenticated remote attacker to manipulate inputs to the function, forcing the server to perform unauthorized HTTP requests to arbitrary destinations. This could potentially be leveraged to access internal metadata services, cloud infrastructure resources, or internal network services not intended for public access. The vulnerability is publicly disclosed, and no official patch has been provided by the vendor, as they did not respond to initial disclosure efforts.

## Attack Chain

1. Attacker identifies the publicly accessible scale Endpoint in the NASA earthdata-search application.
2. Attacker crafts a malicious request targeting the scaleImage handler function.
3. Attacker injects a target URL into the input parameter processed by the scaleImage function.
4. The server-side application fails to validate or sanitize the attacker-provided URL.
5. The application performs a backend HTTP GET or POST request to the attacker-specified target.
6. Attacker observes the response or network impact to exfiltrate data or probe internal network architecture.

## Impact

Successful exploitation of this vulnerability allows remote attackers to bypass network perimeters, potentially leading to the unauthorized disclosure of internal data, sensitive information from internal cloud metadata services, or the ability to interact with other internal-only API endpoints within the environment.

## Recommendation

Prioritize the identification of internet-facing instances of NASA earthdata-search 1.0.0 within the environment. If the software is deployed, implement egress filtering at the network level to prevent the server from reaching internal resources or unauthorized external domains. Monitor web server logs for suspicious requests containing URL parameters that deviate from expected patterns within the scaleImage handler endpoint.
