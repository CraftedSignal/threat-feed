---
title: OpenClaw Nostr DM Unauthorized Crypto Computation Vulnerability
slug: 2026-04-openclaw-unauth-crypto
description: The openclaw npm package before version 2026.3.22 allows unauthorized pre-authentication computation due to improper handling of inbound Nostr DMs, where crypto and dispatch work are performed before enforcing sender and pairing policies.
date: "2026-03-26T19:09:45Z"
severities:
  - high
tags:
  - supply-chain
  - vulnerability
  - npm
references:
  - https://github.com/advisories/GHSA-65h8-27jh-q8wv
rules:
  - title: Detect OpenClaw Nostr Processing Before Auth
    description: Detects potential exploitation of the OpenClaw Nostr DM vulnerability by monitoring for access to specific files before authorization is performed.
    platform: sigma
    severity: high
    tactics:
      - dos
    techniques:
      - T1499
    data_sources:
      - file_event
      - linux
  - title: Detect High CPU Usage by OpenClaw Process After DM
    description: Detects potential denial-of-service attacks by monitoring for high CPU usage by the OpenClaw process immediately following network connections on the DM port.
    platform: sigma
    severity: medium
    tactics:
      - dos
    techniques:
      - T1499
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The `openclaw` npm package, a tool likely used for decentralized communication or cryptocurrency-related applications, contains a vulnerability affecting versions prior to 2026.3.22. Specifically, the vulnerability lies in the handling of inbound Direct Messages (DMs) within the Nostr protocol implementation. The flaw allows for crypto operations and dispatch work to be triggered before proper sender and pairing policy enforcement. This means an attacker could potentially initiate…
