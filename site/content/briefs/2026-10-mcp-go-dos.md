---
title: Denial of Service Vulnerability in mcp-go
slug: 2026-10-mcp-go-dos
description: mcp-go versions through 1.2.1 contain a denial of service vulnerability in StreamableHTTPServer.ServeHTTP that allows remote, unauthenticated attackers to trigger memory exhaustion via oversized POST request bodies.
date: "2026-10-11T16:02:48Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:mcp-go:mcp-go:*:*:*:*:*:*:*:*
products:
  - mcp-go (<= 1.2.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Remote unauthenticated attackers can exhaust memory by sending oversized POST bodies, leading to OOM-kill of the server process.
    confidence_band: high
cves:
  - id: CVE-2026-108859
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108859
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade mcp-go to a version greater than 1.2.1 to remediate CVE-2026-108859
      owner: IT Operations
      due: 48h
      evidence: Source documentation identifies version 1.2.1 as the affected upper bound.
  mitigation_plan:
    - priority: immediate
      action: Configure reverse proxy or WAF to reject POST requests exceeding reasonable size thresholds
      owner: Infrastructure
      addresses: CVE-2026-108859
      evidence: Remediation via request size restriction prevents large payload delivery.
---

mcp-go versions through 1.2.1 are susceptible to a denial of service (DoS) vulnerability located within the StreamableHTTPServer.ServeHTTP function. The vulnerability is caused by an unsafe implementation where the server reads the entirety of an incoming POST request body into memory using the io.ReadAll function before any validation logic is executed. This design flaw allows remote, unauthenticated attackers to transmit either a single arbitrarily large POST body or multiple concurrent requests, rapidly consuming the available memory of the host process. Successful exploitation leads to memory exhaustion, causing the server process to crash or be terminated by the operating system's out-of-memory (OOM) killer. This impacts the availability of any service relying on the mcp-go library for handling HTTP streams.

## Impact

Successful exploitation of this vulnerability results in a denial of service for the affected application. Because the impact is memory exhaustion, the entire service process may terminate, requiring manual intervention or automated restart procedures to recover. This affects any infrastructure or internal service components that have integrated mcp-go versions 1.2.1 or earlier for handling HTTP communication.

## Recommendation

- Upgrade the mcp-go library to a version later than 1.2.1 where request body validation occurs prior to buffering or where memory limits are enforced during read operations.
- Implement request body size limits at the load balancer or reverse proxy layer (e.g., Nginx client_max_body_size) to prevent excessively large payloads from reaching the application server.
- Audit custom HTTP server implementations using mcp-go to ensure that io.ReadAll is not used on unvalidated request streams.
