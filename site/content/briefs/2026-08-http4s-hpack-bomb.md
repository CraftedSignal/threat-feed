---
title: http4s Ember Backend HTTP/2 HPACK Bomb Denial of Service
slug: 2026-08-http4s-hpack-bomb
description: The http4s Ember backend is vulnerable to a denial of service attack via HPACK bomb due to improper header size accounting, allowing remote attackers to trigger Java heap memory exhaustion.
date: "2026-08-26T14:19:57Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
vendors:
  - http4s
products:
  - http4s-ember-core
---

The http4s Ember backend contains a vulnerability in its HTTP/2 implementation involving the handling of HPACK-compressed headers. Specifically, the implementation concatenates header and continuation frames before decoding, but fails to account for indexed headers within the configured maximum header size limit. An attacker can exploit this by sending specially crafted, compact HTTP/2 header packets that expand into significantly larger data structures during the decoding process. This malicious payload forces the application to allocate substantial memory, leading to an OutOfMemory (OOM) error. Observed in testing, approximately five concurrent connections against a 2GB heap are sufficient to crash the server. This vulnerability, identified as CVE-2026-54556, affects http4s versions up to 0.23.34 and 1.0.0-M46 across various Scala binary versions. Because no existing configuration can mitigate this while keeping HTTP/2 enabled, immediate action is required.

## Attack Chain

1. Attacker establishes multiple concurrent TCP connections to an http4s server or client utilizing the Ember backend.
2. Attacker initiates an HTTP/2 session over these established connections.
3. Attacker sends a series of malicious HPACK-compressed header and continuation frames designed to bypass internal accounting mechanisms.
4. The Hpack wrapper in the Ember core concatenates these frames without verifying against the effective maximum header size limit.
5. The application attempts to decode the malicious payload into a large list object in the JVM memory space.
6. The memory allocation exceeds the allocated Java heap space.
7. The application service crashes with a java.lang.OutOfMemoryError, resulting in a denial of service.

## Impact

Successful exploitation results in a denial of service for affected http4s servers and clients. The vulnerability allows unauthenticated remote attackers to crash instances with relatively low request volume, potentially impacting any environment running http4s services exposed to untrusted traffic.

## Recommendation

Prioritized actions for detection and mitigation:
* Disable HTTP/2 support in all http4s Ember configurations immediately until a patched version is deployed.
* Monitor application server logs for recurrent `java.lang.OutOfMemoryError` exceptions that correlate with HTTP/2 traffic patterns to identify active exploitation attempts.
* Audit all internet-facing services to identify and isolate instances running http4s versions 0.23.34 or earlier and 1.0.0 versions prior to M46.
* Prioritize updating to the vendor-provided patch once the fix threading the maxHeaderSize into the Hpack decoding logic is applied to your specific environment.
