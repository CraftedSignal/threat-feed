---
title: Netty HttpClientCodec Response Desynchronization Vulnerability
slug: 2024-01-netty-desync
description: The Netty HttpClientCodec is vulnerable to response desynchronization when configured with HTTP/1.1 pipelining, HEAD requests, and the server sends 1xx responses, leading to a response body from one request being parsed as another and potentially unsafe socket reuse.
date: "2024-01-03T18:22:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - netty
  - http
  - desynchronization
  - vulnerability
vendors:
  - Netty
products:
  - netty-codec-http (>= 4.2.0.Alpha1, <= 4.2.12.Final)
  - netty-codec-http (<= 4.1.132.Final)
references:
  - https://github.com/advisories/GHSA-57rv-r2g8-2cj3
rules:
  - title: Detect Netty HttpClientCodec Response Desync Error
    description: Detects HTTP responses with decoder failures potentially indicating a Netty HttpClientCodec response desynchronization vulnerability (CVE-2026-42584).
    platform: sigma
    severity: high
    tactics:
      - impact
    data_sources:
      - webserver
      - linux
  - title: Detect Early Hints followed by OK Response
    description: Detects a sequence of HTTP 103 Early Hints response immediately followed by a 200 OK, potentially indicating conditions for the Netty HttpClientCodec vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - impact
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A response desynchronization vulnerability exists in Netty's `HttpClientCodec` when HTTP/1.1 pipelining is enabled, HEAD requests are present in the request pipeline, and the server sends 1xx responses. This occurs because the `HttpClientCodec` incorrectly pairs inbound responses with outbound requests, specifically when a server sends a 1xx response followed by a 200 response with a body for a GET request, and then a 200 response for a subsequent HEAD request. The `HttpClientCodec` may incorrectly pair the HEAD request with the first 200 response, skipping the message body and causing subsequent responses to be parsed from the wrong offset. This can lead to data integrity issues and potentially unsafe socket reuse. The vulnerability affects Netty versions 4.2.0.Alpha1 through 4.2.12.Final and all versions up to 4.1.132.Final.

## Attack Chain

1. The attacker initiates a series of HTTP/1.1 requests, including a GET request followed by a HEAD request, leveraging HTTP pipelining for efficiency.
2. The malicious client sends a GET request for a resource (e.g., `/1`) immediately followed by a HEAD request for another resource (e.g., `/2`).
3. The vulnerable Netty server processes the GET request and sends a 103 Early Hints response, followed by a 200 OK response containing the body of the GET request (e.g., "hello").
4. The server then processes the HEAD request and sends a 200 OK response without a body, as is standard for HEAD requests.
5. The `HttpClientCodec` on the client side incorrectly pairs the HEAD request with the initial 200 OK response from the GET request, due to the intervening 103 response.
6. The `HttpClientCodec` skips the GET response body ("hello") when processing the HEAD response, leaving those bytes unread on the input stream.
7. The subsequent HTTP response is then parsed from the wrong offset in the input stream, leading to parsing failures or incorrect data being associated with the wrong request.
8. The attacker can exploit this desynchronization to potentially inject malicious content or intercept sensitive data meant for other requests, compromising the integrity and availability of the connection.

## Impact

Successful exploitation of this vulnerability can lead to a loss of integrity and availability of HTTP parsing, causing incorrect or incomplete data to be processed by the client application. This can result in application errors, data corruption, or the exposure of sensitive information. Furthermore, the unsafe reuse of the socket could lead to further exploitation of the compromised connection. While the exact number of affected systems is unknown, any application relying on the vulnerable versions of Netty's `HttpClientCodec` and utilizing HTTP/1.1 pipelining with HEAD requests is potentially at risk.

## Recommendation

*   Upgrade to a patched version of Netty that addresses CVE-2026-42584. Specifically, upgrade beyond version 4.2.12.Final or version 4.1.132.Final.
*   If upgrading Netty is not immediately feasible, consider disabling HTTP/1.1 pipelining as a temporary mitigation. This will prevent the conditions necessary for the desynchronization to occur.
*   Deploy the Sigma rule `Detect Netty HttpClientCodec Response Desync Error` to identify potential exploitation attempts by monitoring for HTTP responses with decoder failures after a series of pipelined requests.
