---
title: libp2p-rendezvous Unlimited Namespace Registration DoS
slug: 2026-04-libp2p-rendezvous-dos
description: A vulnerable libp2p-rendezvous server can be crashed via a denial-of-service attack where an unauthenticated peer registers unlimited namespaces, leading to memory exhaustion.
date: "2026-04-04T06:33:46Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - libp2p
  - rendezvous
  - denial-of-service
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://github.com/advisories/GHSA-cqfx-gf56-8x59
rules:
  - title: Detect Excessive Namespace Registrations from Single Peer
    description: Detects a high number of unique namespace registration requests from a single peer within a short time frame, indicating potential DoS attack.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
      - linux
  - title: Detect Rendezvous Server Memory Usage Spike
    description: Detects a significant increase in memory usage by the libp2p-rendezvous server process, which may indicate a DoS attack.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The `libp2p-rendezvous` server prior to version 0.17.1 is susceptible to a denial-of-service (DoS) attack. An attacker can exploit the lack of limitations on namespace registrations per peer. By repeatedly registering unique namespaces, the server allocates memory without restriction, leading to an out-of-memory (OOM) crash. This vulnerability requires no authentication, allowing any peer on the network to initiate the attack. The issue stems from the `Registrations::add()` function in `protocols/rendezvous/src/server.rs`, which does not enforce a maximum number of registrations per peer. The `MAX_TTL` of 72 hours exacerbates the problem, as registrations persist for up to three days even if the peer disconnects.

## Attack Chain

1.  Attacker connects to a publicly accessible `libp2p-rendezvous` server.
2.  Attacker sends a REGISTER request to the server for a unique namespace.
3.  The server's `Registrations::add()` function processes the request and adds the namespace to its internal data structures (`registrations_for_peer`, `registrations`, `next_expiry`).
4.  The attacker repeats steps 2 and 3 in a loop, registering thousands of unique namespaces.
5.  The server continues to allocate memory for each namespace registration.
6.  Due to the `MAX_TTL` of 72 hours, previously registered namespaces are not removed from memory.
7.  The server's memory consumption increases steadily with each registered namespace.
8.  The server process eventually exhausts available memory (OOM) and crashes, disrupting peer discovery services for legitimate clients.

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service condition, making the `libp2p-rendezvous` server unavailable. Any rust-libp2p based project that deploys a rendezvous point is at risk. Since rendezvous servers are often well-known and publicly reachable, their downtime disrupts peer discovery for all clients relying on them. The impact scales with the number of attacking peers, requiring only a single connection and REGISTER requests to achieve the DoS. The affected package is `rust/libp2p-rendezvous` versions prior to 0.17.1.

## Recommendation

*   Upgrade to `rust/libp2p-rendezvous` version 0.17.1 or later to patch CVE-2026-35405.
*   Monitor resource utilization (CPU, memory) of `libp2p-rendezvous` server processes to detect anomalous spikes indicative of a DoS attack.
*   Implement rate limiting on namespace registration requests from individual peers in the application layer.
