---
title: libp2p-gossipsub Remote Denial of Service via Integer Overflow
slug: 2026-03-libp2p-gossipsub-dos
description: A remote, unauthenticated attacker can crash applications using libp2p-gossipsub versions prior to 0.49.4 by sending a crafted PRUNE control message with a near-maximum backoff value, causing an arithmetic overflow during heartbeat processing.
date: "2026-03-30T13:04:03Z"
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

The Rust libp2p Gossipsub implementation, a peer-to-peer networking library, is susceptible to a remote denial-of-service (DoS) vulnerability. This flaw resides in the handling of `backoff` expiry during heartbeat processing. By sending a specially crafted `PRUNE` control message containing an attacker-controlled, near-maximum `backoff` value, a remote, unauthenticated peer can trigger an integer overflow. This overflow occurs when the implementation performs unchecked addition of the…
