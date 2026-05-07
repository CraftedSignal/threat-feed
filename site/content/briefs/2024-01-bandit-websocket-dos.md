---
title: Bandit WebSocket Memory Exhaustion Vulnerability
slug: 2024-01-bandit-websocket-dos
description: An unauthenticated attacker can exhaust server memory by sending unbounded WebSocket continuation frames in Bandit-fronted applications, leading to a denial of service.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - websocket
  - memory-exhaustion
vendors:
  - Phoenix Framework
products:
  - Phoenix Channels
  - LiveView
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.004
    technique_name: Application Layer Protocol
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070.001
    technique_name: Indicator Removal on Host
references:
  - https://github.com/advisories/GHSA-pf94-94m9-536p
rules:
  - title: Detect WebSocket Connections Without FIN Bit
    description: Detects WebSocket connections that initiate and send data but do not close with a FIN bit set, which could indicate a DoS attempt.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - linux
  - title: Detect Excessive WebSocket Continuation Frames
    description: Detects a large number of WebSocket continuation frames being sent from a single source IP within a short period, potentially indicating a memory exhaustion attack.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A vulnerability exists in Bandit, a web server for Elixir, where a single unauthenticated WebSocket client can exhaust server memory. The vulnerability stems from the fragmented-message reassembly path, which appends every `Continuation{fin: false}` frame's payload to a per-connection iolist without any cumulative size cap. This allows an attacker to stream continuation frames indefinitely (without setting `fin=1`), causing the BEAM heap to grow linearly until the operating system or a supervisor terminates the process. This issue affects applications using Phoenix Channels and LiveView, as they rely on `WebSock` on Bandit. The exploit is effective even with common deployment topologies, including L4 load balancers and HTTP-mode reverse proxies. The recommended fix involves tracking a running cumulative byte count on the connection state and introducing a configurable `max_message_size`.

## Attack Chain

1.  Establish a WebSocket connection with a Bandit-fronted application.
2.  Send a WebSocket text frame with the `fin` bit set to `0`.
3.  Send a series of WebSocket continuation frames with the `fin` bit set to `0`.
4.  Each continuation frame's payload is appended to a per-connection iolist.
5.  The iolist grows linearly in BEAM memory as continuation frames are sent without limit.
6.  The attacker does not send a final frame with `fin=1`, preventing the iolist from being processed and cleared.
7.  The server's memory consumption increases until it reaches the system limit.
8.  The server process is terminated due to excessive memory usage, causing a denial of service.

## Impact

The vulnerability allows for unauthenticated denial-of-service attacks via memory exhaustion. A single connection can consume gigabytes of BEAM heap, and a small number of concurrent connections can cause the host to run out of memory. This affects any Phoenix application that accepts WebSocket connections, including those using Phoenix Channels and LiveView. The absence of a mitigation strategy makes applications vulnerable by default. A successful attack can lead to service disruption and downtime.

## Recommendation

*   Monitor network traffic for WebSocket connections sending a large number of continuation frames without a final frame (fin=1).
*   Implement rate limiting for WebSocket connections to mitigate the impact of a single client exhausting resources.
*   Apply the suggested fix by tracking a running cumulative byte count on the connection state and adding a configurable `max_message_size` as described in the overview.
*   Monitor BEAM memory usage on systems running Bandit web servers to detect anomalous memory consumption.
*   Deploy the Sigma rule to detect websocket connections not sending the FIN bit.
