---
title: HTTP Request Smuggling Vulnerability in tiny-http CVE-2026-66752
slug: 2026-07-tiny-http-request-smuggling
description: A critical HTTP request smuggling vulnerability (CVE-2026-66752) exists in tiny-http versions up to and including 0.12.0, allowing remote attackers to desynchronize request framing by sending a Transfer-Encoding header with arbitrary values, causing the library to incorrectly apply chunk-decoding and ignore Content-Length, which enables request smuggling attacks and can lead to denial of service by tying up connections and consuming worker threads.
date: "2026-07-28T16:22:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - http-request-smuggling
  - vulnerability
  - denial-of-service
  - webserver
vendors:
  - tiny-http
products:
  - tiny-http <= 0.12.0
cves:
  - id: CVE-2026-66752
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66752
---

A remote attacker can exploit CVE-2026-66752, an HTTP request smuggling vulnerability present in tiny-http versions through 0.12.0. This flaw allows an attacker to manipulate how the tiny-http server interprets HTTP requests, particularly when it is behind a front-end proxy that correctly handles HTTP framing. By sending a `Transfer-Encoding` header with any value, even non-chunked ones, the tiny-http library incorrectly applies chunk-decoding and discards the `Content-Length` header. This discrepancy in parsing leads to desynchronization of request framing between the proxy and the vulnerable server, enabling request smuggling attacks. Furthermore, attackers can trigger failed body reads by sending non-chunked bodies with specific `Transfer-Encoding` values, which can exhaust server resources by tying up connections and consuming worker threads without notifying clients, effectively leading to a denial of service.

## Attack Chain

1. Attacker identifies a web server running tiny-http (version 0.12.0 or earlier) potentially behind a reverse proxy or load balancer.
2. Attacker crafts an HTTP request containing a `Transfer-Encoding` header set to a non-chunked value (e.g., `Transfer-Encoding: invalid-encoding`).
3. The request also includes a `Content-Length` header for the initial part of the request.
4. The front-end proxy correctly processes the `Transfer-Encoding` and `Content-Length` headers according to HTTP specifications and forwards the byte stream to the tiny-http server.
5. The vulnerable tiny-http server, upon receiving the `Transfer-Encoding` header, unconditionally attempts to apply chunk-decoding and discards the `Content-Length` value.
6. This misinterpretation causes a desynchronization in request framing between the proxy and the tiny-http server, allowing the tiny-http server to incorrectly interpret subsequent legitimate requests as part of the attacker's initial request (request smuggling).
7. Alternatively, sending a non-chunked body with the specific `Transfer-Encoding` value can trigger failed body reads.
8. These failed reads exhaust server resources by tying up connections and consuming worker threads, resulting in a denial of service for legitimate users.

## Impact

The primary impact of this vulnerability is HTTP request smuggling, which can lead to various further attacks such as bypassing security controls (e.g., WAFs, access controls), cache poisoning, and session hijacking. Additionally, the vulnerability can be exploited for denial of service (DoS), as failed body reads can consume server resources, leading to connection exhaustion and worker thread starvation without providing error feedback to clients. This can render the affected tiny-http based applications unavailable to legitimate users.

## Recommendation

* Upgrade all instances of tiny-http to a version patched against CVE-2026-66752 immediately to prevent exploitation.
* Review web server and proxy configurations to ensure they strictly adhere to RFC specifications for HTTP header parsing and request framing, especially concerning `Transfer-Encoding` and `Content-Length` headers, to mitigate HTTP request smuggling risks.
