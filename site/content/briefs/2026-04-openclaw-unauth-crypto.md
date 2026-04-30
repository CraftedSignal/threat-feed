---
title: OpenClaw Nostr DM Unauthorized Crypto Computation Vulnerability
slug: 2026-04-openclaw-unauth-crypto
description: The openclaw npm package before version 2026.3.22 allows unauthorized pre-authentication computation due to improper handling of inbound Nostr DMs, where crypto and dispatch work are performed before enforcing sender and pairing policies.
date: "2026-03-26T19:09:45Z"
type: advisory
types:
  - advisory
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

The `openclaw` npm package, a tool likely used for decentralized communication or cryptocurrency-related applications, contains a vulnerability affecting versions prior to 2026.3.22. Specifically, the vulnerability lies in the handling of inbound Direct Messages (DMs) within the Nostr protocol implementation. The flaw allows for crypto operations and dispatch work to be triggered before proper sender and pairing policy enforcement. This means an attacker could potentially initiate resource-intensive computations on a vulnerable system without proper authentication or authorization. The issue was reported by @kuranikaran and resolved in version 2026.3.22 with improvements to authorization checks in `extensions/nostr/src/channel.ts` and the introduction of pre-crypto authorization and rate-limiting guardrails in `extensions/nostr/src/nostr-bus.ts`.

## Attack Chain

1.  Attacker crafts a malicious Nostr DM specifically designed to trigger computationally expensive crypto operations within OpenClaw.
2.  Attacker sends the malicious DM to a user running a vulnerable version of the `openclaw` package.
3.  The OpenClaw application receives the DM and, due to the vulnerability, proceeds to decrypt the message content before validating the sender's authorization.
4.  OpenClaw attempts to perform cryptographic operations, such as decryption or signature verification, based on the contents of the malicious DM.
5.  The application dispatches internal tasks or events based on the decrypted (but unauthorized) message content.
6.  Repeatedly sending these crafted messages can lead to denial of service due to CPU exhaustion or memory over-utilization.
7.  (If applicable) Depending on the purpose of the cryptographic operations, the attacker may be able to glean partial information or influence the application's state without full authentication.

## Impact

Successful exploitation of this vulnerability could lead to denial-of-service conditions due to excessive CPU usage and memory consumption on systems running vulnerable versions of OpenClaw. Attackers could potentially trigger resource-intensive cryptographic operations without proper authorization, impacting the availability and performance of the application. In specific scenarios, and depending on the application's functionality, partial information disclosure or unauthorized state changes might be possible. This vulnerability affects any application using the `openclaw` npm package prior to version 2026.3.22.

## Recommendation

*   Upgrade the `openclaw` npm package to version 2026.3.22 or later to remediate the vulnerability (reference affected versions).
*   Monitor network traffic for unusually high volumes of inbound Nostr DM messages targeting applications using the `openclaw` package (network_connection log source).
*   Implement rate limiting on Nostr DM processing to prevent denial-of-service attacks (network_connection/firewall log source).
*   Deploy the provided Sigma rule to detect suspicious activity related to the vulnerable code paths (process_creation/file_event log source).
