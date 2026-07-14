---
title: Netty StompSubframeDecoder Denial of Service Vulnerability (CVE-2026-44891)
slug: 2026-07-netty-dos
description: A high-severity denial of service vulnerability, identified as CVE-2026-44891, exists in the `StompSubframeDecoder` component of Netty's `netty-codec-stomp` library, allowing an unauthenticated attacker to exhaust server memory and cause an `OutOfMemoryError` by sending a STOMP message with an excessive number of headers, leading to application crashes.
date: "2026-07-14T20:38:25Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - netty
  - java
  - application-layer
vendors:
  - Netty Project
products:
  - netty-codec-stomp (4.2.x)
  - netty-codec-stomp (4.1.x)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
    evidence: |-
      An attacker can send a large number of short headers (e.g., `a: 1
      `), which are accumulated in memory inside the `DefaultStompHeadersSubframe` until the JVM throws an OutOfMemoryError.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-vhch-2wf3-m8rp
---

A high-severity denial of service vulnerability, CVE-2026-44891, has been identified in the `StompSubframeDecoder` component of the Netty `netty-codec-stomp` library. This vulnerability affects versions `netty-codec-stomp` >= 4.2.0.Alpha1 and <= 4.2.15.Final, as well as versions <= 4.1.135.Final. The `StompSubframeDecoder`, responsible for implementing the STOMP protocol, fails to impose limits on the total number or cumulative size of headers within a single STOMP frame. An unauthenticated attacker can exploit this flaw by sending a specially crafted STOMP message containing a large volume of short headers. This leads to an uncontrolled accumulation of headers in memory, causing the Java Virtual Machine (JVM) to throw an `OutOfMemoryError` and subsequently crash the server application. This vulnerability poses a significant risk to any server exposing a STOMP endpoint utilizing the affected Netty components.

## Attack Chain

1. An attacker identifies a target system running an application that uses the vulnerable Netty `netty-codec-stomp` library.
2. The attacker crafts a malicious STOMP `CONNECT` message, specifically designed to include an exceptionally large number of short, arbitrary headers (e.g., `a:1\n`).
3. The attacker sends this malformed STOMP message over the network to the vulnerable server's STOMP endpoint.
4. Upon receipt, the `StompSubframeDecoder` component processes the incoming message, accumulating the unbounded headers in memory.
5. Due to the lack of limits on total header count or cumulative size, this accumulation rapidly consumes the available heap memory of the Java Virtual Machine (JVM) hosting the server application.
6. The JVM experiences a critical `OutOfMemoryError`, leading to an abrupt termination of the server application.
7. The application crash results in a Denial of Service (DoS), rendering the service unavailable to legitimate users.

## Impact

The successful exploitation of CVE-2026-44891 leads directly to a Denial of Service (DoS) for affected applications. An attacker can easily exhaust the server's memory by sending a single, maliciously crafted STOMP message, causing the Java Virtual Machine (JVM) to encounter an `OutOfMemoryError` and crash the application. This renders the service completely unavailable to legitimate users, potentially causing significant operational disruption and financial losses depending on the nature and criticality of the affected system. While specific victim counts are not provided, any server exposing a STOMP endpoint built with the vulnerable `StompSubframeDecoder` is susceptible.

## Recommendation

* Upgrade the `netty-codec-stomp` library to a patched version immediately to remediate CVE-2026-44891.
* Review network traffic logs for STOMP `CONNECT` messages that contain an unusually high number of headers or exhibit rapid increases in payload size, indicative of attempts to exploit CVE-2026-44891.
* Monitor Java Virtual Machine (JVM) memory usage and application logs for `OutOfMemoryError` exceptions that may indicate a successful denial of service attack related to CVE-2026-44891.
