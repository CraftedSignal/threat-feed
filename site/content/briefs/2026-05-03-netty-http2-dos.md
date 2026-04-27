---
title: Netty HTTP/2 CONTINUATION Frame Flood Denial of Service
slug: 2026-05-03-netty-http2-dos
description: A denial of service vulnerability exists in Netty's HTTP/2 server implementation where an unauthenticated user can exhaust server CPU resources by sending a flood of CONTINUATION frames with zero-byte payloads, bypassing size-based mitigations and leading to service unavailability with minimal bandwidth usage; affected versions include netty-codec-http2 < 4.1.132.Final and netty-codec-http2 versions >= 4.2.0.Alpha1 and < 4.2.10.Final.
date: "2026-03-26T18:51:14Z"
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

The Netty HTTP/2 CONTINUATION Frame Flood vulnerability (CVE-2026-33871) allows a remote, unauthenticated user to trigger a Denial of Service (DoS) condition on a Netty-based HTTP/2 server. This is achieved by sending a flood of HTTP/2 `CONTINUATION` frames, each containing a zero-byte payload. The vulnerability exists because Netty's `DefaultHttp2FrameReader` does not enforce a limit on the number of `CONTINUATION` frames it processes after receiving a `HEADERS` frame without the `END_HEADERS`…
