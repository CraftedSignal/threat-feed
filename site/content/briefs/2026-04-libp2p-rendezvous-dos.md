---
title: libp2p-rendezvous Unlimited Namespace Registration DoS
slug: 2026-04-libp2p-rendezvous-dos
description: A vulnerable libp2p-rendezvous server can be crashed via a denial-of-service attack where an unauthenticated peer registers unlimited namespaces, leading to memory exhaustion.
date: "2026-04-04T06:33:46Z"
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

The `libp2p-rendezvous` server prior to version 0.17.1 is susceptible to a denial-of-service (DoS) attack. An attacker can exploit the lack of limitations on namespace registrations per peer. By repeatedly registering unique namespaces, the server allocates memory without restriction, leading to an out-of-memory (OOM) crash. This vulnerability requires no authentication, allowing any peer on the network to initiate the attack. The issue stems from the `Registrations::add()` function in…
