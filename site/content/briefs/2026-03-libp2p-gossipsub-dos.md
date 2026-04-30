---
title: libp2p-gossipsub Remote Denial of Service via Integer Overflow
slug: 2026-03-libp2p-gossipsub-dos
description: A remote, unauthenticated attacker can crash applications using libp2p-gossipsub versions prior to 0.49.4 by sending a crafted PRUNE control message with a near-maximum backoff value, causing an arithmetic overflow during heartbeat processing.
date: "2026-03-30T13:04:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - libp2p
  - gossipsub
  - denial-of-service
  - integer overflow
  - rust
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-xqmp-fxgv-xvq5
rules:
  - title: Detect libp2p Gossipsub PRUNE with Large Backoff
    description: Detects abnormally large backoff values within libp2p Gossipsub PRUNE messages, indicating a potential DoS attack.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - zeek
  - title: Detect libp2p Gossipsub Connection Attempts
    description: Detects connections to libp2p Gossipsub service.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1016
    data_sources:
      - network_connection
      - zeek
rules_count: 2
---

The Rust libp2p Gossipsub implementation, a peer-to-peer networking library, is susceptible to a remote denial-of-service (DoS) vulnerability. This flaw resides in the handling of `backoff` expiry during heartbeat processing. By sending a specially crafted `PRUNE` control message containing an attacker-controlled, near-maximum `backoff` value, a remote, unauthenticated peer can trigger an integer overflow. This overflow occurs when the implementation performs unchecked addition of the `backoff_time` and a `slack` value. This vulnerability affects applications using libp2p-gossipsub versions prior to 0.49.4 and is distinct from CVE-2026-33040, which addressed overflow during backoff insertion. This report highlights a distinct secondary overflow path in heartbeat expiry handling that remained exploitable even after the initial insertion-side hardening. The vulnerability was reported by the Security team of the Ethereum Foundation.

## Attack Chain

1. An attacker establishes a standard libp2p session with a target node using `TCP + Noise` for encryption.
2. The attacker negotiates a stream multiplexer protocol such as `mplex` or `yamux`.
3. The attacker opens a Gossipsub stream with the target node to initiate communication.
4. The attacker sends an RPC (Remote Procedure Call) containing a `ControlPrune` message.
5. The `ControlPrune` message includes a crafted `backoff` value set near the maximum representable value for an i64 integer (e.g., `9223372036854674580`). The attacker chooses this value relative to the victim's uptime.
6. The target node parses the `backoff` value from the protobuf message and processes it using `Behaviour::handle_prune()`.
7. The `backoff` value is stored after a checked addition to ensure it's valid, however the near-maximum value is still retained.
8. On the next heartbeat, the node attempts to calculate the expiry time by adding a `slack` value to the stored `backoff_time` using unchecked addition, which results in an integer overflow, causing a panic and crashing the application.

## Impact

This vulnerability results in a remote, unauthenticated denial of service. Any application exposing an affected `libp2p-gossipsub` listener can be crashed by a network-reachable peer. The crash occurs during heartbeat processing, not immediately upon receiving the `PRUNE` message. The attack can be repeated by reconnecting to the target and replaying the crafted `PRUNE` message. This could lead to service disruptions and potential data loss if the application does not handle crashes gracefully. The number of potential victims is significant, encompassing any application utilizing vulnerable versions of the `libp2p-gossipsub` library.

## Recommendation

*   Upgrade the `libp2p-gossipsub` dependency to version 0.49.4 or later to patch the unchecked arithmetic operation that causes the overflow.
*   Deploy the Sigma rule "Detect libp2p Gossipsub PRUNE with Large Backoff" to identify potential exploitation attempts by monitoring network traffic for unusually large `backoff` values in `PRUNE` messages.
*   Enable network connection logging to capture details of libp2p sessions and identify potential malicious peers attempting to exploit this vulnerability (logsource: network_connection).
