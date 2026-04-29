---
title: Netty HTTP/2 CONTINUATION Frame Flood Denial of Service
slug: 2026-05-03-netty-http2-dos
description: A denial of service vulnerability exists in Netty's HTTP/2 server implementation where an unauthenticated user can exhaust server CPU resources by sending a flood of CONTINUATION frames with zero-byte payloads, bypassing size-based mitigations and leading to service unavailability with minimal bandwidth usage; affected versions include netty-codec-http2 < 4.1.132.Final and netty-codec-http2 versions >= 4.2.0.Alpha1 and < 4.2.10.Final.
date: "2026-03-26T18:51:14Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - denial-of-service
  - http2
  - netty
  - cve-2026-33871
references:
  - https://github.com/advisories/GHSA-w9fj-cfpg-grvv
rules:
  - title: Detect Netty HTTP/2 CONTINUATION Frame Flood Attempt
    description: Detects a potential HTTP/2 CONTINUATION frame flood attack against a Netty server based on the number of CONTINUATION frames within a short time period.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
      - linux
rules_count: 1
---

The Netty HTTP/2 CONTINUATION Frame Flood vulnerability (CVE-2026-33871) allows a remote, unauthenticated user to trigger a Denial of Service (DoS) condition on a Netty-based HTTP/2 server. This is achieved by sending a flood of HTTP/2 `CONTINUATION` frames, each containing a zero-byte payload. The vulnerability exists because Netty's `DefaultHttp2FrameReader` does not enforce a limit on the number of `CONTINUATION` frames it processes after receiving a `HEADERS` frame without the `END_HEADERS` flag. The zero-byte payload bypasses the `maxHeaderListSize` protection, as this protection is only triggered when the added payload has a non-zero length. This forces the server to consume excessive CPU resources, monopolizing a connection thread and rendering the server unresponsive to legitimate requests. This vulnerability impacts Netty versions prior to 4.1.132.Final and versions between 4.2.0.Alpha1 and 4.2.10.Final.

## Attack Chain

1. The attacker establishes a TCP connection to the targeted Netty HTTP/2 server.
2. The attacker sends an HTTP/2 `HEADERS` frame to initiate a new stream. The `END_HEADERS` flag is deliberately omitted from this frame.
3. The server, upon receiving the `HEADERS` frame without the `END_HEADERS` flag, prepares to receive subsequent `CONTINUATION` frames.
4. The attacker floods the server with a series of `CONTINUATION` frames, each containing a zero-byte payload. These frames are sent over the established TCP connection.
5. The `DefaultHttp2FrameReader` processes each `CONTINUATION` frame, but the `verifyContinuationFrame()` method fails to enforce a limit on the number of received frames.
6. The `HeadersBlockBuilder.addFragment()` method processes the zero-byte payload, bypassing the `maxHeaderListSize` protection. The server CPU continues to process the stream of `CONTINUATION` frames.
7. The server exhausts CPU resources on the connection thread, as it is continuously processing the flood of `CONTINUATION` frames.
8. Legitimate users are unable to connect to the server or experience significant delays due to the server's unresponsiveness. This leads to a denial of service.

## Impact

This vulnerability leads to a CPU-based Denial of Service (DoS). All services using the vulnerable Netty HTTP/2 server implementation are susceptible. An unauthenticated attacker can exhaust server CPU resources, preventing legitimate users from accessing the service. The minimal bandwidth requirement for this attack makes it practical and scalable, allowing an attacker to disrupt services with limited resources. Successful exploitation results in service unavailability, impacting business operations and user experience.

## Recommendation

*   Upgrade to Netty version 4.1.132.Final or 4.2.10.Final or later to patch CVE-2026-33871.
*   Implement rate limiting on HTTP/2 `CONTINUATION` frames to mitigate the impact of a flood attack. Consider implementing this at the application level if upgrading Netty is not immediately feasible.
*   Monitor CPU usage on servers running Netty HTTP/2 services. Alert on sustained high CPU usage, which may indicate an ongoing attack.
*   Deploy the Sigma rules provided in this brief to detect potential exploitation attempts in your environment.
