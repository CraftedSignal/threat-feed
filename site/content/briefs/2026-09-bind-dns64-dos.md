---
title: BIND 9 Denial of Service via Malformed DNS64 Response
slug: 2026-09-bind-dns64-dos
description: A vulnerability in BIND 9 resolvers configured with DNS64 allows an authoritative server to cause a process crash through malformed responses, resulting in a denial of service.
date: "2026-09-16T15:51:04Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:isc:bind:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - network-infrastructure
  - vulnerability
vendors:
  - ISC
products:
  - BIND (9.11.0-9.18.50)
  - BIND (9.20.0-9.20.27)
  - BIND (9.21.0-9.21.25)
  - BIND (9.11.3-S1-9.18.50-S1)
  - BIND (9.20.9-S1-9.20.27-S1)
cves:
  - id: CVE-2026-19666
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19666
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Network Security
  mitigation_plan:
    - priority: immediate
      action: Upgrade BIND 9 installations to versions containing the patch for CVE-2026-19666
      owner: IT Operations
      addresses: CVE-2026-19666
      evidence: Source NVD advisory confirms the vulnerability in specific BIND versions
  gaps:
    - Lack of specific IDS signatures for the malformed response prevents blocking at the network edge.
---

The Internet Systems Consortium (ISC) BIND 9 software contains a vulnerability (CVE-2026-19666) that affects resolvers specifically configured to utilize the DNS64 function. When the resolver receives a maliciously crafted or malformed response from an authoritative DNS server, the `named` process encounters an unhandled state, causing the service to exit unexpectedly. This leads to a denial of service (DoS) for all clients relying on the affected resolver. The vulnerability impacts a wide range of BIND 9 versions, including the 9.11, 9.20, and 9.21 branches, as well as their subscription versions. Because this requires an authoritative server to provide specific malformed data, the scope of risk is primarily limited to environments where the resolver configuration allows for such upstream responses, or where an attacker can influence the traffic returned to the recursive resolver.

## Impact

Successful exploitation results in the immediate termination of the `named` process. In production environments, this causes a complete outage of DNS resolution services for the affected infrastructure, preventing internal and external network communication dependent on name resolution.

## Recommendation

Prioritize patching affected BIND 9 instances to the latest secure version provided by ISC. Because this is a crash-inducing vulnerability, monitor DNS server logs for unexpected service restarts or frequent `named` process terminations. Review configuration files to identify if `dns64` is enabled, as this is a prerequisite for the vulnerability.
