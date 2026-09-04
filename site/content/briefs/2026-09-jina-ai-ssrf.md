---
title: SSRF Vulnerability in Jina AI Reader via Incomplete Redirect Validation
slug: 2026-09-jina-ai-ssrf
description: Jina AI reader is vulnerable to Server-Side Request Forgery (SSRF) due to improper URL validation during HTTP redirects, allowing access to internal network or cloud metadata services.
date: "2026-09-04T15:32:13Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:jina:reader:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - web-vulnerability
vendors:
  - Jina AI
products:
  - jina-ai reader
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: jina-ai reader contains a server-side request forgery vulnerability where URL validation is performed only on the initial request but not re-applied to subsequent redirect hops.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1530
    technique_name: Data from Cloud Storage Object
    evidence: Attackers can craft a public URL that redirects to internal network addresses or cloud metadata endpoints, allowing the server to fetch and return the target's response body.
    confidence_band: high
cves:
  - id: CVE-2026-85699
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85699
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Audit Jina AI reader deployments and restrict egress traffic to internal network and cloud metadata addresses.
      owner: Security Engineering
      due: 48h
      evidence: CVE-2026-85699 documentation of SSRF via redirect
  mitigation_plan:
    - priority: immediate
      action: Upgrade jina-ai reader to the vendor-provided patched version.
      owner: IT Operations
      addresses: CVE-2026-85699
      evidence: NVD vulnerability disclosure
---

Jina AI reader is susceptible to a Server-Side Request Forgery (SSRF) vulnerability identified as CVE-2026-85699. The flaw exists because the application performs URL validation exclusively on the initial request URL. If the initial URL returns an HTTP redirect, the application follows the subsequent location header without re-validating the final destination against the same security policies. This allows an attacker to supply a legitimate-looking URL that redirects to internal-only endpoints, such as local network services (e.g., localhost, 127.0.0.1) or cloud metadata service endpoints (e.g., 169.254.169.254). By chaining these redirects, an attacker can coerce the application into fetching sensitive internal content and returning the response data to the user, potentially leading to unauthorized data exposure or interaction with internal APIs.

## Impact

The vulnerability allows an attacker to perform SSRF attacks, which can lead to the exfiltration of sensitive configuration data, cloud credentials from instance metadata services, or the reconnaissance of internal network infrastructure. Successful exploitation could compromise internal services that are not designed to be exposed to the internet.

## Recommendation

- Ensure that the Jina AI reader application is updated to the latest available version that patches the redirect validation logic for CVE-2026-85699.
- Implement strict allowlists for destination URLs to ensure that the application only requests permitted domains.
- Configure network-level egress filtering to prevent the application from making outbound requests to internal IP ranges (e.g., 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and link-local addresses (169.254.169.254) unless strictly necessary.
