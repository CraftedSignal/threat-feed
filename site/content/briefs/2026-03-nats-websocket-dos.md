---
title: NATS Server WebSocket Frame Length Overflow Denial of Service
slug: 2026-03-nats-websocket-dos
description: A vulnerability in NATS server allows a remote, unauthenticated attacker to cause a denial of service by sending a crafted WebSocket frame, leading to a server crash due to missing validation on WebSocket frame length.
date: "2026-03-26T12:00:00Z"
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

A critical vulnerability exists in NATS server versions 2.2.0 through 2.11.13 and 2.12.0 through 2.12.4, enabling unauthenticated remote attackers to trigger a denial-of-service (DoS) condition. The vulnerability stems from a missing sanity check on WebSocket frame lengths, allowing malicious clients to send crafted frames that cause a server panic and crash. This issue impacts deployments that utilize WebSockets and expose the network port to untrusted endpoints. The attack requires no…
