---
title: Denial of Service in Netty HTTP/3 Codec via QPACK Encoder State Exhaustion
slug: 2026-09-netty-qpack-dos
description: An unauthenticated remote attacker can cause heap exhaustion in applications using Netty's HTTP/3 codec by exploiting improper QPACK dynamic table state management, leading to a denial-of-service condition.
date: "2026-09-26T15:07:39Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:netty:netty-codec-http3:4.2.0.final:*:*:*:*:*:*:*
  - cpe:2.3:a:netty:netty-codec-http3:4.2.17.final:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - java
  - networking
vendors:
  - Netty
products:
  - netty-codec-http3 (4.2.0.Final - 4.2.17.Final)
cves:
  - id: CVE-2026-100660
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100660
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade netty-codec-http3 to version 4.2.18.Final
      owner: IT Operations
      due: 48h
      evidence: Fixed in 4.2.18.Final.
  mitigation_plan:
    - priority: immediate
      action: Apply rate limiting and stream count restrictions on HTTP/3 traffic at the edge
      owner: Network Engineering
      addresses: CVE-2026-100660
      evidence: A remote, unauthenticated HTTP/3 client can... bypass concurrent-stream limits.
---

Netty's HTTP/3 codec (io.netty:netty-codec-http3) versions 4.2.0.Final through 4.2.17.Final are susceptible to a memory exhaustion vulnerability (CVE-2026-100660). The issue stems from the QpackEncoder component, which retains an unbounded queue and dynamic-table index tracker for every encoded field section referencing the QPACK dynamic table. These objects are stored in memory keyed by the peer-controlled QUIC stream ID and are released exclusively upon receipt of a Section Acknowledgment or Stream Cancellation instruction from the remote decoder. 

Because the implementation lacks limits on the number of tracked streams, field sections, or total retained bytes, an unauthenticated attacker can orchestrate a denial-of-service attack. By initiating sequential HTTP/3 requests over a single QUIC connection while omitting mandatory Section Acknowledgments, an attacker forces the server to accumulate entries indefinitely. This bypasses typical concurrent-stream constraints and consumes server heap memory until the process crashes. Defenders should upgrade to version 4.2.18.Final to incorporate the enforced state management and limits.

## Impact

Successful exploitation results in a persistent denial-of-service state due to heap exhaustion. The vulnerability affects any application utilizing the netty-codec-http3 library version 4.2.0.Final through 4.2.17.Final for HTTP/3 traffic. Because the attack occurs at the HTTP/3 protocol layer, it can impact any public-facing service or microservice infrastructure relying on these specific Netty versions for QUIC/HTTP/3 connectivity.

## Recommendation

- Upgrade netty-codec-http3 to version 4.2.18.Final or later across all Java applications immediately.
- Review HTTP/3 traffic ingress patterns for clients that exhibit high rates of request initiation without corresponding acknowledgment traffic, which may indicate attempted exploitation.
- Apply resource limits on the number of concurrent QUIC streams and total HTTP/3 memory usage at the network load balancer or reverse proxy layer as a temporary mitigation for services that cannot be patched immediately.
- Monitor Java Virtual Machine (JVM) heap usage metrics for unusual growth spikes occurring concurrently with HTTP/3 traffic volume.
