---
title: CVE-2026-93488 Denial of Service in Netty SpdySessionHandler
slug: 2026-09-netty-dos
description: The Netty SpdySessionHandler component is vulnerable to a denial of service attack via uncontrolled concurrent stream allocation, potentially exhausting JVM heap and direct memory.
date: "2026-09-18T14:05:58Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:netty:netty:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - java
  - networking
vendors:
  - Netty
products:
  - Netty (all versions)
cves:
  - id: CVE-2026-93488
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93488
action_plan:
  priority: elevated
  owners:
    - SOC
    - Engineering
  immediate_actions:
    - action: Inventory all Java applications utilizing Netty libraries for SPDY usage.
      owner: Engineering
      due: 72h
      evidence: Source document identifies Netty as the vulnerable component.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to the version of Netty that restricts concurrent streams or disables SPDY.
      owner: Engineering
      addresses: CVE-2026-93488
      evidence: Source identifies vulnerability as a lack of API-based control for stream limits.
---

CVE-2026-93488 is a high-severity vulnerability discovered in the Netty framework's SPDY implementation. The `SpdySessionHandler` fails to restrict the number of concurrent remote-initiated streams because the `localConcurrentStreams` setting defaults to `Integer.MAX_VALUE`, and the library provides no API to modify this threshold.

An unauthenticated remote attacker can exploit this by establishing a SPDY connection and initiating a flood of `SYN_STREAM` frames with the `FLAG_FIN` flag set to 0. Because the handler does not bound these streams, each request forces the application to allocate memory on the JVM heap and in direct memory buffers. Sustained exploitation leads to memory exhaustion, triggering a `java.lang.OutOfMemoryError` and resulting in a denial of service (DoS) for the affected service. Given Netty's widespread use in high-performance networking applications, this vulnerability poses a significant risk to the availability of systems relying on the SPDY protocol.

## Impact

Successful exploitation results in a complete denial of service for the targeted Netty-based application. Since the vulnerability resides within the low-level transport handler, an attacker can crash the JVM by sending specially crafted, resource-intensive SPDY control frames, potentially leading to widespread downtime for critical infrastructure components.

## Recommendation

Detection and mitigation teams should prioritize identifying applications utilizing the SPDY protocol with vulnerable versions of the Netty framework.

1. Inventory all Java applications utilizing the `io.netty:netty-codec-http2` or `netty-all` libraries to identify instances where the `SpdySessionHandler` is enabled.
2. Implement monitoring for JVM memory usage, specifically tracking `java.lang.OutOfMemoryError` exceptions that correlate with increased network traffic from external SPDY peers.
3. Patch applications to the version of Netty that introduces a configuration API or restrictive default for `localConcurrentStreams` as identified in official Netty security bulletins.
4. If patching is not immediately feasible, consider disabling SPDY support at the load balancer or reverse proxy level if the protocol is not strictly required for business operations.
