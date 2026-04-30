---
title: OpenClaw Unauthenticated WebSocket Denial-of-Service Vulnerability
slug: 2026-04-openclaw-dos
description: OpenClaw before 2026.3.28 is vulnerable to a denial-of-service attack by accepting unbounded concurrent unauthenticated WebSocket upgrades, allowing attackers to exhaust server resources.
date: "2026-04-28T19:37:43Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - websocket
  - cve
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
cves:
  - id: CVE-2026-41399
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41399
rules:
  - title: Detect Excessive WebSocket Upgrade Requests
    description: Detects a high number of WebSocket upgrade requests within a short timeframe, potentially indicating a denial-of-service attempt.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
      - linux
  - title: Detect High Volume of WebSocket Upgrade Requests from Single IP
    description: Detects a high volume of websocket upgrade requests from a single IP address
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - firewall
rules_count: 2
---

OpenClaw, in versions prior to 2026.3.28, suffers from a denial-of-service vulnerability due to a lack of pre-authentication budget allocation for WebSocket upgrades. This flaw allows unauthenticated network attackers to initiate a large number of concurrent WebSocket upgrade requests without any resource constraints. By exploiting this, an attacker can exhaust the server's socket and worker capacity, effectively preventing legitimate clients from establishing WebSocket connections and disrupting normal service operation. This vulnerability poses a risk to any OpenClaw deployment accessible over a network, as it can be exploited without requiring any prior authentication or privileged access.

## Attack Chain

1. An unauthenticated attacker identifies an OpenClaw server accessible over the network.
2. The attacker sends a large number of WebSocket upgrade requests to the server. These requests are crafted to initiate the WebSocket handshake process.
3. The OpenClaw server accepts these requests without pre-authentication checks or resource limits.
4. Each incoming WebSocket upgrade request consumes server resources, including sockets and worker threads.
5. The attacker continues to flood the server with upgrade requests, rapidly exhausting available resources.
6. As resources become scarce, the server's ability to handle legitimate client requests degrades.
7. Eventually, the server's socket and worker capacity is fully exhausted, leading to a denial-of-service condition.
8. Legitimate clients are unable to establish WebSocket connections, disrupting application functionality.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition, preventing legitimate users from accessing OpenClaw services. The number of affected users depends on the scale of the OpenClaw deployment and the number of concurrent users it typically supports. Organizations relying on OpenClaw for critical functions could experience significant disruptions and potential data loss if the service becomes unavailable. The vulnerability allows a single attacker to disrupt the service without requiring any credentials or prior access.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.28 or later to remediate the vulnerability (CVE-2026-41399).
*   Implement rate limiting on WebSocket upgrade requests to mitigate the impact of malicious requests. Deploy the Sigma rule `Detect Excessive WebSocket Upgrade Requests` to identify suspicious activity.
*   Monitor network traffic for a high volume of WebSocket upgrade requests originating from a single source IP address. Use the Sigma rule `Detect High Volume of WebSocket Upgrade Requests from Single IP` to detect this pattern.
