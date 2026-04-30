---
title: NATS Server WebSocket Frame Length Overflow Denial of Service
slug: 2026-03-nats-websocket-dos
description: A vulnerability in NATS server allows a remote, unauthenticated attacker to cause a denial of service by sending a crafted WebSocket frame, leading to a server crash due to missing validation on WebSocket frame length.
date: "2026-03-26T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - nats
  - websocket
  - denial-of-service
  - CVE-2026-27889
  - server-crash
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-pq2q-rcw4-3hr6
rules:
  - title: Detect NATS Server WebSocket Crash Attempt
    description: Detects attempts to crash the NATS server by sending a malicious WebSocket frame with an invalid payload length.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - linux
  - title: Detect NATS Server WebSocket Connection to Port 9222
    description: Detects connections to the NATS Server websocket port. This is not malicious by itself, but can be used as a starting point for further investigation.
    platform: sigma
    severity: informational
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A critical vulnerability exists in NATS server versions 2.2.0 through 2.11.13 and 2.12.0 through 2.12.4, enabling unauthenticated remote attackers to trigger a denial-of-service (DoS) condition. The vulnerability stems from a missing sanity check on WebSocket frame lengths, allowing malicious clients to send crafted frames that cause a server panic and crash. This issue impacts deployments that utilize WebSockets and expose the network port to untrusted endpoints. The attack requires no authentication or credentials and can be executed with a single TCP connection sending a malicious WebSocket frame. This vulnerability was reported by GitHub users Mistz1 and jiayuqi7813.

## Attack Chain

1.  The attacker establishes a TCP connection to the NATS server's WebSocket port.
2.  The attacker sends a WebSocket upgrade request to initiate the WebSocket handshake.
3.  The NATS server completes the WebSocket handshake, establishing a WebSocket connection.
4.  The attacker sends a crafted WebSocket frame with a 64-bit extended payload length field where the most significant bit (MSB) is set (e.g., `0x8000000000000001`).
5.  The server reads the 8-byte payload length but fails to validate that the MSB is zero, resulting in a negative integer value.
6.  The negative value bypasses the bounds clamp in the `wsRead` function.
7.  A slice operation with the negative length triggers a runtime panic due to out-of-bounds access.
8.  The unrecovered panic propagates to the Go runtime, causing the entire NATS server process to terminate, disconnecting all clients.

## Impact

Successful exploitation of this vulnerability results in a complete denial of service, crashing the entire NATS server process. All connected clients, including NATS, WebSocket, MQTT, cluster routes, gateways, and leaf nodes, are immediately disconnected. JetStream in-flight acknowledgments are lost, and Raft consensus is disrupted in clustered deployments. The attack is repeatable on every server restart, causing significant disruption to services relying on the NATS server. Any NATS server deployment with WebSocket listeners enabled is vulnerable.

## Recommendation

*   Upgrade the NATS server to version 2.11.14, 2.12.5, or later to patch CVE-2026-27889.
*   If upgrading is not immediately feasible, restrict access to the WebSocket port to trusted endpoints as a defense-in-depth measure, as mentioned in the overview.
*   Deploy the Sigma rule to detect connections with crafted websocket frame to your SIEM and tune for your environment.
