---
title: Unbounded WebSocket Message Aggregation Leads to Denial of Service in http4s-blaze-server
slug: 2026-07-unbounded-websocket-dos-http4s-blaze
description: A vulnerability in `http4s-blaze-server` allows an attacker to cause a denial of service by exploiting unbounded WebSocket message aggregation, enabling an attacker to drive unbounded heap growth in the server's JVM by sending an unterminated fragmented WebSocket message, leading to an `OutOfMemoryError` and server termination, affecting any http4s application serving WebSocket routes over `BlazeServerBuilder` and triggerable by unauthenticated or authenticated clients.
date: "2026-07-24T22:35:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - webserver
  - jvm
  - websocket
vendors:
  - http4s
products:
  - 'http4s-blaze-server_2.13 (vulnerable: < 0.23.18)'
  - 'http4s-blaze-server_2.13 (vulnerable: >= 1.0.0-M1, < 1.0.0-M42)'
  - 'http4s-blaze-server_2.12 (vulnerable: < 0.23.18)'
  - 'http4s-blaze-server_3 (vulnerable: >= 1.0.0-M1, < 1.0.0-M42)'
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Application Layer Denial of Service
    evidence: '`http4s-blaze-server` aggregates the fragments of an incoming WebSocket message with no limit on total size or fragment count. [...] resulting in denial of service via `OutOfMemoryError`.'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-7ppr-r889-mcf2
---

A critical vulnerability exists in `http4s-blaze-server` versions prior to 0.23.18 and within versions 1.0.0-M1 to 1.0.0-M41, stemming from unbounded WebSocket message aggregation. Attackers can exploit this by establishing a WebSocket connection and sending fragmented messages without setting the final (FIN) bit. The server, particularly when using `BlazeServerBuilder`, buffers these fragments without any size limit, irrespective of the `maxWebSocketBufferSize` setting which only applies to individual frames. This leads to continuous and uncontrolled heap memory growth in the server's Java Virtual Machine (JVM). Ultimately, this resource exhaustion results in an `OutOfMemoryError` and the termination of the JVM process, effectively causing a Denial of Service (DoS) for the affected http4s application. Both unauthenticated and authenticated clients can trigger this vulnerability, depending on the WebSocket endpoint's exposure, making it a severe threat to the availability of affected services.

## Attack Chain

1. An attacker establishes a WebSocket connection with a vulnerable http4s-blaze-server application.
2. The attacker sends an initial WebSocket message fragment.
3. The attacker continues to send a series of subsequent WebSocket message fragments.
4. These fragments intentionally do not set the `FIN` (final fragment) bit, indicating an unterminated message.
5. The `http4s-blaze-server` buffers all incoming fragments of this unterminated message without an aggregate size limit.
6. Due to the lack of an aggregate size limit, the server's JVM heap memory grows uncontrollably as fragments accumulate.
7. The server's JVM encounters an `OutOfMemoryError` as it exhausts available memory resources.
8. This `OutOfMemoryError` leads to the termination of the server JVM, resulting in a Denial of Service for the affected http4s application.

## Impact

Any http4s application that serves WebSocket routes over `BlazeServerBuilder` is directly impacted by this vulnerability. Successful exploitation leads to an `OutOfMemoryError` within the server's JVM, causing it to terminate. This results in complete unavailability of the affected application, leading to a Denial of Service. The `maxWebSocketBufferSize` configuration parameter does not mitigate this issue as it only limits individual frame sizes, not the aggregated message size. A single malicious connection can exhaust the server's heap, even with a modest volume of wire bytes if many small fragments are used, amplifying the per-frame object overhead. The attacker can be unauthenticated if the WebSocket endpoint is publicly reachable or an authenticated client if the handshake requires authentication.

## Recommendation

* Terminate or limit WebSocket traffic at a fronting layer (e.g., a reverse proxy or load balancer) that enforces message-size and fragment count limits, or disable WebSocket routes entirely on affected `http4s-blaze-server` instances.
* Plan migration to a maintained backend (e.g., http4s-ember) as the upstream `blaze` server is End-of-Life, addressing the root cause in affected `http4s-blaze-server` versions.
