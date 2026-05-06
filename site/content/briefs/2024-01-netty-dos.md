---
title: Netty epoll Transport Denial of Service via RST on Half-Closed TCP Connection
slug: 2024-01-netty-dos
description: Netty's epoll transport fails to properly close TCP connections that receive a RST after a half-close, leading to resource exhaustion and potential CPU busy-loops, impacting service availability.
date: "2026-05-06T23:10:41Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - netty
  - epoll
  - resource-exhaustion
vendors:
  - Netty
products:
  - netty-transport-native-epoll ( < 4.2.13.Final)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-rwm7-x88c-3g2p
  - https://github.com/netty/netty/issues/16683
  - https://github.com/netty/netty/pull/16689
  - https://github.com/netty/netty/commit/0ec3d97fab376e243d328ac95fbd288ba0f6e22d
rules:
  - title: Detect High CPU Usage by Netty Event Loop Threads
    description: Detects sustained high CPU usage by threads associated with Netty's event loop, potentially indicating a busy-loop caused by CVE-2026-42577.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Excessive TCP Connection Attempts to a Single Port
    description: Detects a high number of TCP connection attempts to a single port, which may indicate an attacker trying to exploit CVE-2026-42577.
    platform: sigma
    severity: low
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A denial-of-service vulnerability exists in Netty's epoll transport for versions 4.2.x up to and including 4.2.12.Final. When `ALLOW_HALF_CLOSURE` is enabled (or when using the HTTP codec), if a remote peer sends a FIN (half-close) followed by a RST, the server-side channel is not properly closed. This can lead to stale channels accumulating, exhausting file descriptors, memory, or connection count limits. In certain code paths, it can also trigger a 100% CPU busy-loop in the event loop thread, starving other connections. This vulnerability allows an unauthenticated remote attacker to cause a denial of service. The issue is resolved in version 4.2.13.Final.

## Attack Chain

1. A client establishes a TCP connection with a Netty-based server using the epoll transport.
2. The server configures the connection with `ALLOW_HALF_CLOSURE` enabled or uses the HTTP codec which can result in a half-closed state.
3. The client sends a FIN packet to initiate a half-close of the TCP connection, signaling that it will no longer send data.
4. The server acknowledges the FIN and marks the input side of the channel as shutdown.
5. The client abruptly terminates the connection by sending a RST packet (e.g., by closing the socket with `SO_LINGER=0`).
6. Due to a flaw in Netty's epoll transport, the server fails to process the `EPOLLERR` or `EPOLLHUP` event triggered by the RST.
7. The `channelInactive` event is never fired, leaving the channel in a stale state.
8. An attacker repeats this process, accumulating stale channels and exhausting server resources, potentially leading to a CPU busy-loop and a denial-of-service condition.

## Impact

Successful exploitation of this vulnerability can lead to a denial-of-service condition. An unauthenticated remote attacker can exhaust server resources like file descriptors, memory, and connection limits, or trigger a CPU busy-loop. This can render the affected Netty-based service unavailable, impacting legitimate users. The number of potential victims depends on the scale of the deployment and the server's resource capacity.

## Recommendation

*   Upgrade to Netty version 4.2.13.Final or later to patch CVE-2026-42577 and resolve the vulnerability.
*   If upgrading is not immediately feasible, configure idle timeouts on connections to limit the lifetime of stale channels, mitigating the resource exhaustion impact.
*   Monitor CPU utilization of Netty event loop threads. Investigate processes with high CPU usage for extended periods to identify potential exploitation of this vulnerability.
*   Implement rate limiting on new TCP connections from individual source IPs to reduce the effectiveness of connection exhaustion attacks.
