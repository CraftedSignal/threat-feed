---
title: Unauthenticated SSRF in Kan API Endpoint
slug: 2026-10-kan-ssrf
description: Kan versions 0.5.5 through 0.6.0 contain an unauthenticated SSRF vulnerability in the /api/download/attatchment endpoint that allows attackers to probe internal services and cloud metadata.
date: "2026-10-14T16:37:12Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:kan:kan:0.5.5:*:*:*:*:*:*:*
  - cpe:2.3:a:kan:kan:0.6.0:*:*:*:*:*:*:*
  - cpe:2.3:a:kan:kan:*:*:*:*:*:*:*:*
tags:
  - web-application
  - ssrf
  - cloud-security
vendors:
  - Kan
products:
  - Kan (0.5.5 - 0.6.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Kan 0.5.5 through 0.6.0 contains an unauthenticated server-side request forgery vulnerability in the /api/download/attatchment route.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1595.002
    technique_name: 'Active Scanning: Vulnerability Scanning'
    evidence: Attackers can pass arbitrary url query parameters to fetch() to read internal services, localhost ports, and cloud instance metadata.
    confidence_band: high
cves:
  - id: CVE-2026-32255
    cvss: 8.6
    epss: 0.01744
  - id: CVE-2026-110628
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110628
---

Kan versions 0.5.5 through 0.6.0 are affected by an unauthenticated server-side request forgery (SSRF) vulnerability located in the /api/download/attatchment route. This vulnerability arises from an incomplete remediation of CVE-2026-32255. When the S3_ENDPOINT environment variable is not configured, the application fails to properly validate parameters passed to the internal fetch() function. An unauthenticated attacker can exploit this to submit arbitrary URLs as query parameters, forcing the application server to make requests on their behalf. This permits the exfiltration of sensitive information, such as cloud instance metadata (e.g., AWS/GCP/Azure IMDS endpoints), and enables scanning of the internal network for reachable services and open ports. Defenders should treat this as a high-priority risk if the affected Kan instances are deployed within cloud environments or have access to sensitive internal network segments.

## Impact

Successful exploitation allows remote, unauthenticated attackers to bypass network perimeters, potentially leading to the compromise of cloud instance credentials, unauthorized access to internal administrative interfaces, or the discovery of internal network topography. The vulnerability exposes any internal resource accessible from the server's network location.

## Recommendation

* Immediately upgrade to a patched version of Kan or configure the S3_ENDPOINT environment variable to an authenticated, trusted endpoint to neutralize the vulnerability trigger.
* Monitor web server logs for requests to /api/download/attatchment that contain internal IP addresses (e.g., 169.254.169.254, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) in the query parameters.
* Restrict the outbound network access of the Kan application server to only authorized external endpoints to prevent exploitation of the SSRF for internal network probing.
