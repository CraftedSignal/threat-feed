---
title: Netty XmlFrameDecoder CPU Exhaustion Denial of Service
slug: 2026-07-netty-xmlframedecoder-dos
description: An unauthenticated remote attacker can cause a Denial of Service (DoS) in Netty servers utilizing XmlFrameDecoder by sending a specially crafted XML payload containing repeated '</' characters, leading to CPU exhaustion of the server's EventLoop thread and unresponsiveness.
date: "2026-07-24T16:59:02Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - cpu-exhaustion
  - network-attack
  - vulnerability
vendors:
  - Netty Project
products:
  - netty-codec-xml (4.2.0.Final - 4.2.15.Final)
  - netty-codec-xml (<= 4.1.135.Final)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: An attacker can cause Denial of Service by sending a specially crafted malicious XML payload ... causing the server's EventLoop thread to exhaust CPU resources and become unresponsive.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-v74w-7mr3-4qg3
---

A Denial of Service (DoS) vulnerability has been identified in Netty's `XmlFrameDecoder` component, tracked under CVE-2024-XXXX (although not explicitly assigned in source, it represents a similar class of vulnerability). This flaw allows an unauthenticated remote attacker to exhaust the CPU resources of a Netty server by sending a specially crafted malicious XML payload. Specifically, when the decoder encounters a `<` followed by a `/` character, it attempts to scan the remaining buffer for a closing `>`. Due to the parser's state not being preserved across `decode()` invocations, an attacker can deliver a payload with numerous `</` character sequences in a trickle-feed manner. This forces the decoder to repeatedly rescan the entire accumulated buffer, causing an endless loop and consuming significant CPU on the server's EventLoop thread, ultimately rendering the server unresponsive. This impacts applications using `netty-codec-xml` versions within specific ranges.

## Attack Chain

1. An unauthenticated attacker initiates an HTTP POST request targeting a Netty server configured to process XML input via `XmlFrameDecoder`.
2. The attacker crafts a malicious XML payload for the request body, specifically designed to include a large number of `</` character sequences.
3. The attacker sends this specially crafted XML payload, potentially in a trickle-feed manner, to the vulnerable Netty server.
4. The Netty server's `XmlFrameDecoder` begins processing the incoming XML stream.
5. Upon encountering the `</` sequence within the XML data, the decoder attempts to locate the corresponding closing `>`.
6. Due to the decoder's implementation, which does not save its parsing state between `decode()` calls, it repeatedly rescans the entire accumulated buffer for a closing `>` each time a `</` sequence is processed.
7. This continuous and inefficient rescanning process consumes an excessive amount of CPU resources on the server's EventLoop thread.
8. The EventLoop thread becomes unresponsive due to CPU exhaustion, leading to a complete Denial of Service for the Netty server.

## Impact

Successful exploitation of this vulnerability results in a Denial of Service via CPU exhaustion. Any application utilizing Netty's `XmlFrameDecoder` is susceptible to this attack. An unauthenticated remote attacker can trigger the flaw by sending a relatively modest amount of malformed XML data to an exposed port, causing the server to hang completely. This can lead to significant service disruption, unavailability of critical applications, and potential financial losses for affected organizations.

## Recommendation

* **Patch `netty-codec-xml`**: Immediately update `maven/io.netty:netty-codec-xml` to versions beyond `4.2.15.Final` (for the 4.2.x line) or `4.1.135.Final` (for the 4.1.x line) as specified in the affected products.
* **Monitor CPU utilization**: Implement monitoring for high CPU utilization on servers processing XML input with Netty, as sustained high usage could indicate an ongoing DoS attack.
* **Implement input validation**: Review and enhance input validation mechanisms for all XML processing endpoints to filter or reject malformed XML payloads before they reach the `XmlFrameDecoder`.
