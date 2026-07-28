---
title: TinyWeb Memory Leak Vulnerability (CVE-2026-67183) Leads to Denial of Service
slug: 2026-07-tinyweb-memory-leak
description: A critical memory leak vulnerability, CVE-2026-67183, in TinyWeb versions up to 0.0.8 allows unauthenticated attackers to exhaust server memory by sending ordinary HTTP requests, leading to worker process termination and denial of service.
date: "2026-07-28T17:21:31Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - memory-leak
  - denial-of-service
  - webserver
products:
  - TinyWeb 0.0.8
cves:
  - id: CVE-2026-67183
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67183
---

A critical memory leak vulnerability, identified as CVE-2026-67183, affects TinyWeb versions up to and including 0.0.8, allowing unauthenticated attackers to trigger a denial of service. The vulnerability stems from the `HttpParser::execute()` function, which, when processing ordinary, well-formed HTTP requests, repeatedly allocates memory for `Url`, `HttpHeaders`, and `HttpHeader` objects. These memory allocations are never freed due to missing destructors and unreachable `delete` calls within the application's codebase. Consequently, each incoming request causes the web server's worker resident memory to increase monotonically by approximately 20 to 28 kilobytes. This continuous memory consumption, driven by unauthenticated HTTP requests, ultimately exhausts the available system resources, leading to the termination of the worker process and a resulting denial of service for legitimate users. This vulnerability allows for straightforward exploitation with common web requests.

## Attack Chain

1. An unauthenticated attacker identifies a vulnerable TinyWeb server (version 0.0.8 or earlier) accessible over HTTP.
2. The attacker sends an ordinary, well-formed HTTP request to the vulnerable TinyWeb server.
3. The server's `HttpParser::execute()` function is invoked to process the incoming request.
4. During request parsing, the `HttpParser::execute()` function allocates new `Url` objects, `HttpHeaders` objects, and `HttpHeader` instances using raw `new` expressions.
5. Due to missing destructors and unreachable `delete` calls in the TinyWeb codebase, the memory allocated for these objects is never freed after processing the request.
6. The attacker continuously sends multiple ordinary, well-formed HTTP requests to the server.
7. Each subsequent request causes the web server's worker process resident memory to grow monotonically by approximately 20 to 28 kB.
8. As the memory consumption increases, the worker process eventually exhausts all available memory resources, leading to its termination and rendering the TinyWeb server unresponsive.

## Impact

The successful exploitation of CVE-2026-67183 leads to a denial of service (DoS) condition on the affected TinyWeb server. Unauthenticated attackers can continuously send HTTP requests, causing the server's memory to be consumed until the worker process crashes. This results in the TinyWeb server becoming unresponsive and unavailable to legitimate users, disrupting web services hosted on it. There is no information regarding specific victim counts or targeted sectors, but any organization utilizing vulnerable TinyWeb versions is susceptible to service interruption and potential data loss if the server crashes unexpectedly.

## Recommendation

* Patch CVE-2026-67183 by upgrading TinyWeb to a patched version (newer than 0.0.8) immediately.
* Monitor webserver logs for unusually high rates of HTTP requests from single IP addresses, which could indicate an attempted denial-of-service attack.
* Implement host-based monitoring to track the memory utilization of TinyWeb worker processes and alert on anomalous, continuous memory growth.
* Configure system monitoring to alert on frequent crashes or restarts of the TinyWeb server process.
