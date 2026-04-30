---
title: Tinyproxy HTTP Chunked Encoding Integer Overflow Denial of Service
slug: 2026-03-tinyproxy-dos
description: An integer overflow vulnerability in Tinyproxy's HTTP chunked transfer encoding parser (versions <= 1.11.3) allows an unauthenticated remote attacker to cause a denial of service by sending a crafted chunk size that bypasses validation, leading to resource exhaustion.
date: "2026-03-30T08:16:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - tinyproxy
  - denial-of-service
  - integer-overflow
  - cve-2026-3945
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1498
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3945
rules:
  - title: Detect Suspiciously Large HTTP Chunk Size
    description: Detects HTTP requests with abnormally large chunk sizes, potentially indicating exploitation of CVE-2026-3945.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
      - linux
  - title: Detect HTTP Requests with Large Chunk Sizes via Content Length
    description: Detects HTTP requests that utilize chunked transfer encoding and also set a content length header, which is unusual and may indicate malicious intent.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Tinyproxy, a lightweight HTTP/HTTPS proxy daemon, is vulnerable to an integer overflow in its chunked transfer encoding parser. This vulnerability, identified as CVE-2026-3945, affects versions up to and including 1.11.3. A remote, unauthenticated attacker can exploit this flaw by sending a specially crafted HTTP request containing an invalid chunk size value, such as 0x7fffffffffffffff. The `strtol()` function is used to parse chunk sizes but fails to properly validate overflow conditions, specifically the `ERANGE` error. This bypasses a check designed to prevent negative chunk lengths (`chunklen < 0`). The subsequent signed integer overflow during arithmetic operations leads to the proxy attempting to read an excessively large amount of data, exhausting resources and preventing new connections, effectively causing a denial-of-service condition. Although the upstream has addressed the issue in commit bb7edc4, the latest stable release (1.11.3) remains vulnerable.

## Attack Chain

1.  The attacker sends an HTTP request to the Tinyproxy server.
2.  The HTTP request uses chunked transfer encoding.
3.  The attacker includes a crafted chunk size value, such as 0x7fffffffffffffff (LONG_MAX), within the request headers.
4.  The Tinyproxy server parses the chunk size using `strtol()`.
5.  The `strtol()` function does not adequately validate the integer overflow (errno == ERANGE).
6.  The crafted chunk size bypasses the initial validation check (`chunklen < 0`).
7.  A signed integer overflow occurs during arithmetic operations (`chunklen + 2`).
8.  The proxy attempts to read an extremely large amount of request-body data, exhausting available worker slots and preventing new connections, causing a denial of service (DoS).

## Impact

Successful exploitation of CVE-2026-3945 leads to a denial-of-service condition. The vulnerable Tinyproxy instance becomes unresponsive as it exhausts its available worker slots. This prevents legitimate users from accessing services proxied by the affected server. The impact is significant as it can completely disrupt services reliant on the proxy, affecting all users until the service is manually restarted or patched. The severity is high due to the ease of exploitation (unauthenticated remote attacker) and the potential for widespread service disruption.

## Recommendation

*   Upgrade Tinyproxy to a version patched against CVE-2026-3945 (commit bb7edc4 or later). If an upgrade is not immediately feasible, consider implementing a web application firewall (WAF) rule to filter requests with excessively large chunk sizes to mitigate the vulnerability.
*   Deploy the Sigma rule `Detect Suspiciously Large HTTP Chunk Size` to identify requests with abnormally large chunk sizes within HTTP traffic, indicating potential exploitation attempts of CVE-2026-3945.
*   Monitor web server logs for HTTP requests with chunk sizes exceeding a reasonable threshold. Analyze the request patterns to identify potential malicious actors attempting to exploit this vulnerability using the `webserver` log source.
