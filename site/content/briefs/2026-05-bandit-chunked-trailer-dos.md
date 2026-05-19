---
title: Bandit HTTP/1 Chunked Request Trailer Denial of Service
slug: 2026-05-bandit-chunked-trailer-dos
description: 'Bandit versions 1.6.0 through 1.11.0 are vulnerable to an unauthenticated denial-of-service (CVE-2026-39806) via a chunked request with trailers, where sending a request with `Transfer-Encoding: chunked` and a trailer field causes the connection''s worker process to spin forever in an infinite recursion, exhausting the listener pool and rendering the server unresponsive.'
date: "2026-05-19T19:26:58Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - bandit
  - chunked-transfer-encoding
vendors:
  - erlang
products:
  - bandit (>= 1.6.0, < 1.11.1)
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-39806
    epss: 0.00556
references:
  - https://github.com/advisories/GHSA-rf5q-vwxw-gmrf
  - https://github.com/mtrudel/bandit/commit/e73e379ab59840e8561b5730878f16e29ab06217
rules:
  - title: Detect Bandit Chunked Trailer DoS Attempt
    description: Detects CVE-2026-39806 exploitation — HTTP POST requests with chunked transfer encoding and trailer fields sent to a Bandit server, indicating a potential denial-of-service attempt.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - webserver
  - title: Detect Suspicious HTTP Request with Chunked Encoding and Trailer
    description: Detects suspicious HTTP requests using chunked transfer encoding and trailer fields, potentially indicative of the Bandit DoS vulnerability (CVE-2026-39806).
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - webserver
rules_count: 2
---

A worker-pinning denial-of-service vulnerability exists in Bandit's HTTP/1 chunked transfer decoder (CVE-2026-39806). The vulnerability affects Bandit versions 1.6.0 through 1.11.0. Any unauthenticated client sending a `Transfer-Encoding: chunked` request with a body ending with a trailer field causes the connection's worker process to become stuck in an infinite recursion. This occurs because the `do_read_chunked_data!/5` function in `lib/bandit/http1/socket.ex` does not properly handle trailer fields in chunked requests, leading to repeated calls to `read_available!/2` without progress. A small number of concurrent connections can exhaust the listener pool, rendering the server unresponsive to further traffic. The vulnerability was introduced with commit e73e379ab59840e8561b5730878f16e29ab06217 on December 6, 2024.

## Attack Chain

1. An attacker sends an HTTP POST request to the vulnerable Bandit server.
2. The request includes the `Transfer-Encoding: chunked` header to indicate a chunked transfer encoding.
3. The request body consists of at least one data chunk followed by the last-chunk marker `0\r\n`.
4. The request body then includes a trailer field, such as `X-Trailer: value\r\n`, after the last chunk marker.
5. The request is terminated with `\r\n` to signal the end of the message.
6. The `do_read_chunked_data!/5` function in `lib/bandit/http1/socket.ex` attempts to parse the chunked data.
7. Due to the presence of the trailer field, the function fails to match the terminator clause and enters the `_ ->` arm, leading to a negative `to_read` value and a call to `read_available!/2`.
8. The function tail-recurses with the same state, causing an infinite loop and pinning the worker process, ultimately leading to denial of service.

## Impact

Successful exploitation results in an unauthenticated denial-of-service condition. A small number of attacker-controlled connections can exhaust the available worker pool, rendering the server unreachable for legitimate users. This impacts any Bandit-fronted HTTP/1 service that accepts chunked request bodies, including Phoenix and Plug applications. Servers behind proxies forwarding trailer-bearing requests are also vulnerable.

## Recommendation

*   Apply the vendor-supplied patch to upgrade to Bandit version 1.11.1 or later, which resolves the vulnerability (reference: https://github.com/advisories/GHSA-rf5q-vwxw-gmrf).
*   Deploy the Sigma rule `Detect Bandit Chunked Trailer DoS Attempt` to identify requests exploiting this vulnerability in your environment (reference: Sigma rule below).
*   Monitor web server logs for HTTP POST requests with `Transfer-Encoding: chunked` and trailer fields (reference: `webserver` log source).
