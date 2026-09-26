---
title: Denial-of-Service Vulnerability in Netty io.netty:netty-codec-http
slug: 2026-09-netty-dos
description: A memory exhaustion vulnerability in Netty's SpdySessionHandler allows remote attackers to trigger JVM OutOfMemoryErrors via unbounded concurrent SPDY stream allocation.
date: "2026-09-26T15:06:56Z"
lastmod: "2026-09-26T17:00:14Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:netty:netty:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - java
vendors:
  - Netty
products:
  - netty-codec-http (<= 4.1.137.Final, 4.2.0.Final - 4.2.17.Final)
  - netty-codec-http (4.2.0.Final <= 4.2.16.Final, <= 4.1.136.Final)
cves:
  - id: CVE-2026-100655
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100655
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100666
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade netty-codec-http to version 4.1.138.Final or 4.2.18.Final
      owner: IT Operations
      due: 48h
      evidence: Fixed in 4.1.138.Final and 4.2.18.Final.
  mitigation_plan:
    - priority: immediate
      action: Identify services using vulnerable Netty versions via dependency scanning
      owner: Security Engineering
      addresses: CVE-2026-100655
      evidence: Netty (io.netty:netty-codec-http) versions up to and including 4.1.137.Final and from 4.2.0.Final through 4.2.17.Final.
updates:
  - at: "2026-09-26T17:00:14Z"
    level: L2
    summary: added coverage for netty-codec-http (4.2.0.Final <= 4.2.16.Final, <= 4.1.136.Final)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-100666
---

Netty (io.netty:netty-codec-http) versions up to and including 4.1.137.Final and from 4.2.0.Final through 4.2.17.Final contain a vulnerability in the SpdySessionHandler component. The handler defaults the maximum number of local concurrent streams to Integer.MAX_VALUE and lacks an API to override this limit. An attacker can initiate a SPDY connection and flood the target server with a high volume of SYN_STREAM frames where the FLAG_FIN bit is set to zero. This forces the server to allocate unbounded heap and direct memory to maintain the session state, eventually exhausting available system memory and triggering a JVM OutOfMemoryError. This leads to a complete service disruption for any application utilizing the affected Netty codec. The vulnerability is addressed in versions 4.1.138.Final and 4.2.18.Final.

## Impact

Successful exploitation results in a persistent denial-of-service condition affecting any Java application relying on the affected Netty codec for SPDY protocol support. This can lead to service downtime for critical infrastructure, APIs, and microservices. The impact is significant for organizations providing high-availability services where memory exhaustion leads to application crashes or service instability.

## Recommendation

- Upgrade the Netty (io.netty:netty-codec-http) library to version 4.1.138.Final or 4.2.18.Final immediately to resolve CVE-2026-100655.
- Review network infrastructure logs to identify anomalous spikes in SPDY traffic or sustained connections from single remote peers that do not terminate streams.
- If immediate patching is not possible, implement network-level rate limiting or SPDY protocol inspection to block traffic from unverified sources attempting to establish an excessive number of concurrent streams.
