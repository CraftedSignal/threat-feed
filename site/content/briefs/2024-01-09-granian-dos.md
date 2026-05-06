---
title: Granian WebSocket Subprotocol Header Denial of Service
slug: 2024-01-09-granian-dos
description: Granian versions 1.2.0 through 2.7.3 are vulnerable to an unauthenticated denial of service. Sending a WebSocket upgrade request with a `Sec-WebSocket-Protocol` header containing non-ASCII bytes causes a worker process to abort, leading to a denial of service.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - websocket
  - granian
vendors:
  - emmett-framework
products:
  - granian
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://github.com/advisories/GHSA-vrg7-482j-p6f6
rules:
  - title: Detect Granian WebSocket Subprotocol DoS Attempt
    description: Detects attempts to exploit the Granian WebSocket subprotocol denial-of-service vulnerability by identifying non-ASCII characters in the Sec-WebSocket-Protocol header.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
      - linux
  - title: Detect Granian WebSocket Subprotocol DoS Attempt (Alternative)
    description: Detects attempts to exploit the Granian WebSocket subprotocol denial-of-service vulnerability by identifying non-ASCII characters in the Sec-WebSocket-Protocol header using a broader range of characters.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Granian, a Python ASGI server, is susceptible to a denial-of-service (DoS) attack affecting versions 1.2.0 through 2.7.3. This vulnerability allows an unauthenticated attacker to crash a worker process by sending a crafted WebSocket upgrade request. The malicious request includes a `Sec-WebSocket-Protocol` header containing non-ASCII bytes. This triggers a panic within Granian's WebSocket scope construction path before the application code is reached. The vulnerability was reported in GHSA-vrg7-482j-p6f6 and assigned CVE-2026-42544. Successful exploitation leads to worker termination, and repeated attacks can bring the entire service offline. This vulnerability highlights the importance of input validation, even in areas seemingly unrelated to application logic.

## Attack Chain

1.  The attacker sends an HTTP GET request to the Granian server, attempting to establish a WebSocket connection.
2.  The request includes standard WebSocket headers such as `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Key`, and `Sec-WebSocket-Version`.
3.  The attacker crafts the `Sec-WebSocket-Protocol` header to include non-ASCII characters (e.g., `\x80\xff`).
4.  Granian's `asgi/utils.rs` code attempts to convert the `Sec-WebSocket-Protocol` header value to a string.
5.  The `HeaderValue::to_str()` function encounters the non-ASCII bytes and returns an error.
6.  The code uses `.unwrap()` on the result, which causes a panic due to the error.
7.  Granian, configured to abort on panic, terminates the worker process.
8.  The service becomes unavailable as workers are repeatedly crashed.

## Impact

This vulnerability results in a denial-of-service condition. An unauthenticated attacker can remotely crash Granian worker processes by sending a single, specially crafted WebSocket request. The application logic is never reached, making application-level authentication ineffective as a mitigation. Repeated requests across multiple workers can lead to complete service outage. This vulnerability affects Granian servers running versions 1.2.0 through 2.7.3.

## Recommendation

*   Upgrade Granian to version 2.7.4 or later to patch CVE-2026-42544.
*   Deploy the Sigma rule `Detect Granian WebSocket Subprotocol DoS Attempt` to identify attempts to exploit this vulnerability by detecting non-ASCII characters in the `Sec-WebSocket-Protocol` header.
*   Enable webserver logging to capture HTTP requests, which are required for the provided Sigma rule.
