---
title: Next.js SSRF Vulnerability via WebSocket Upgrade Requests (CVE-2026-44578)
slug: 2026-05-nextjs-ssrf
description: Next.js applications using WebSocket upgrades are vulnerable to server-side request forgery (SSRF) through crafted WebSocket upgrade requests, allowing attackers to proxy requests to internal or external destinations, affecting self-hosted applications running versions npm/next (>= 13.4.13, < 15.5.16) and npm/next (>= 16.0.0, < 16.2.5).
date: "2026-05-11T15:56:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - cve-2026-44578
  - next.js
  - websocket
  - server-side request forgery
vendors:
  - Vercel
products:
  - next.js
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-c4j6-fc7j-m34r
  - CVE-2026-44578
rules:
  - title: Detect Suspicious WebSocket Upgrade Requests
    description: Detects suspicious WebSocket upgrade requests potentially indicative of CVE-2026-44578 exploitation, focusing on unusual or internal target domains.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect WebSocket Upgrade Requests to Metadata Endpoints
    description: Detects WebSocket upgrade requests targeting common cloud metadata endpoints, which could indicate an SSRF attempt exploiting CVE-2026-44578.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

Next.js applications utilizing WebSocket upgrades are susceptible to a server-side request forgery (SSRF) vulnerability. This flaw allows an attacker to craft WebSocket upgrade requests, forcing the server to proxy requests to arbitrary internal or external destinations. This vulnerability is present in self-hosted Next.js applications using the built-in Node.js server. Vercel-hosted deployments are not affected. The vulnerability is present in versions npm/next (>= 13.4.13, < 15.5.16) and npm/next (>= 16.0.0, < 16.2.5). The fix involves applying the same safety checks to WebSocket upgrade handling that already existed for normal HTTP requests, ensuring upgrade requests are only proxied when routing has explicitly marked them as safe external rewrites. This issue is tracked as CVE-2026-44578.

## Attack Chain

1.  The attacker identifies a self-hosted Next.js application utilizing WebSocket upgrades.
2.  The attacker crafts a malicious WebSocket upgrade request. This request contains a target destination (internal or external) to which the server will be forced to proxy the request.
3.  The attacker sends the crafted WebSocket upgrade request to the Next.js server.
4.  The Next.js server, lacking proper validation, processes the malicious upgrade request.
5.  The server initiates a connection to the attacker-specified destination.
6.  The server proxies data between the attacker and the target destination.
7.  The attacker gains access to internal services, cloud metadata endpoints, or other sensitive resources.
8.  The attacker exfiltrates sensitive information or leverages the access for further malicious activities.

## Impact

Successful exploitation of this SSRF vulnerability (CVE-2026-44578) can lead to the exposure of internal services, cloud metadata endpoints, or other sensitive resources. Attackers can potentially gain unauthorized access to sensitive data or internal systems, leading to data breaches, privilege escalation, or further compromise of the affected infrastructure. The number of victims and the specific sectors targeted depend on the deployment and configurations of the vulnerable Next.js applications. Vercel-hosted deployments are not affected.

## Recommendation

*   Upgrade Next.js to a patched version (>= 15.5.16 or >= 16.2.5) to remediate the vulnerability as described in GHSA-c4j6-fc7j-m34r.
*   Deploy the Sigma rule `Detect Suspicious WebSocket Upgrade Requests` to detect potential exploitation attempts by monitoring for suspicious target domains in WebSocket upgrade requests.
*   If immediate upgrade is not possible, implement the suggested workarounds: do not expose the origin server directly to untrusted networks and block WebSocket upgrades at the reverse proxy or load balancer if they are not required, as described in GHSA-c4j6-fc7j-m34r.
*   Restrict origin egress to internal networks and metadata services where possible, as recommended in GHSA-c4j6-fc7j-m34r.
