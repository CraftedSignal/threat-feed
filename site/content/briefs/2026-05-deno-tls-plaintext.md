---
title: Deno TLS Plaintext Injection Vulnerability
slug: 2026-05-deno-tls-plaintext
description: A vulnerability in Deno's Node.js tls compatibility layer (versions 2.0.0 to 2.7.7) allows a network attacker to intercept and tamper with plaintext application data transmitted over a supposedly TLS-protected connection when `autoSelectFamily` is enabled and the initial connection attempt fails, leading to potential information disclosure and data manipulation.
date: "2026-05-27T19:52:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - deno
  - tls
  - plaintext
  - vulnerability
vendors:
  - rust
products:
  - deno
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-chqv-56wv-7564
  - CVE-2026-44726
rules:
  - title: Detect Deno Plaintext TLS Communication
    description: Detects Deno processes writing sensitive data to network connections before TLS encryption is established, indicating potential exploitation of CVE-2026-44726.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect Deno Process Using Node TLS Module
    description: Detects Deno processes that load the Node.js TLS module, a prerequisite for exploiting CVE-2026-44726.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - image_load
      - windows
rules_count: 2
---

Deno, a modern runtime for JavaScript and TypeScript, contains a flaw within its Node.js tls compatibility layer that can lead to plaintext transmission of sensitive data. Specifically, when using the `node:tls` or `node:https` APIs with the default `autoSelectFamily` option enabled, a failed initial connection attempt can cause a subsequent retry to occur without proper TLS negotiation. This occurs because the socket reinitialization process reuses a stale TLS upgrade hook associated with the original, unsuccessful handle. An attacker who can manipulate network conditions to induce this initial failure can then observe or modify the data transmitted by the client application. This vulnerability affects Deno versions 2.0.0 through 2.7.7 and poses a significant risk to applications relying on TLS for secure communication. The vulnerability is tracked as CVE-2026-44726.

## Attack Chain

1. The victim application initiates a TLS connection using `node:tls` or `node:https` with `autoSelectFamily` enabled.
2. The application resolves the target hostname to multiple IP addresses, including an unreachable address (e.g., IPv6 address).
3. The initial connection attempt to the unreachable address fails (e.g., due to dropped IPv6 traffic).
4. Deno's tls compatibility layer attempts to retry the connection using a different resolved IP address (e.g., IPv4).
5. The socket reinitialization process reuses a stale TLS upgrade hook from the failed connection attempt.
6. The subsequent TCP connection is established without being upgraded to TLS.
7. The victim application writes data to the socket before the `secureConnect` event is triggered. This data includes sensitive information like API keys and card numbers.
8. The attacker intercepts the plaintext data transmitted over the unencrypted TCP connection.

## Impact

Successful exploitation of this vulnerability allows a network attacker to observe and potentially tamper with data that the victim application believes is protected by TLS. This can lead to the disclosure of sensitive information such as API keys, authentication tokens, and financial data like credit card numbers. The proof-of-concept demonstrates the exposure of an `Authorization` header containing a secret bearer token and card details. Applications that transmit sensitive data over TLS using vulnerable versions of Deno are at risk. The number of potential victims is difficult to estimate, but any application using the affected Deno versions with `node:tls` or `node:https` is susceptible.

## Recommendation

*   Upgrade Deno to version 2.7.8 or later to patch CVE-2026-44726.
*   Monitor network traffic for connections to unexpected destinations without TLS negotiation to identify potential exploitation attempts based on the attack chain described above.
*   Consider disabling `autoSelectFamily` in `node:tls` and `node:https` if upgrading is not immediately feasible. This will prevent the vulnerable connection retry behavior, although it may impact connectivity in certain network environments.
*   Implement the "Detect Deno Plaintext TLS Communication" Sigma rule to identify potentially vulnerable Deno processes attempting to communicate without proper TLS encryption.
