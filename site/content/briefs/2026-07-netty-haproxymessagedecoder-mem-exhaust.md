---
title: Netty HAProxyMessageDecoder Vulnerability Leads to Unbounded Memory Exhaustion
slug: 2026-07-netty-haproxymessagedecoder-mem-exhaust
description: A vulnerability, CVE-2026-55851, in Netty's `HAProxyMessageDecoder` can lead to unbounded memory exhaustion when an attacker sends a specific PROXY protocol v2 binary prefix followed by a version byte of `0xFF`, causing a signed-byte sentinel collision that traps the decoder in a version-detection loop and ultimately exhausts the JVM's direct memory allocation, resulting in a denial of service.
date: "2026-07-22T21:24:38Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - memory-exhaustion
  - vulnerability
  - proxy-protocol
vendors:
  - Netty
products:
  - netty-codec-haproxy (>= 4.2.0.Final, <= 4.2.15.Final)
  - netty-codec-haproxy (>= 4.1.0.Final, <= 4.1.135.Final)
cves:
  - id: CVE-2026-55851
references:
  - https://github.com/advisories/GHSA-q6cq-mhr2-jmr5
---

A critical vulnerability, tracked as CVE-2026-55851, has been identified in the `HAProxyMessageDecoder` component within Netty's `codec-haproxy` module. This flaw allows an unauthenticated attacker to trigger an unbounded memory exhaustion, leading to a denial of service (DoS) for applications utilizing the vulnerable Netty versions. The vulnerability arises from an incorrect interpretation of a signed Java `byte` during protocol version detection. Specifically, when an attacker sends a PROXY protocol v2 binary prefix (`0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A`) followed by a `0xFF` version byte, the decoder misinterprets the value due to sign extension. This results in a collision with an internal "need more data" sentinel value, trapping the decoder in an infinite loop where it continuously requests more data without processing or discarding previous input. This behavior causes an unbounded accumulation of inbound bytes in the `cumulation` buffer, ultimately exhausting the Java Virtual Machine's (JVM) direct memory allocation and rendering the affected application unresponsive.

## Attack Chain

1. An attacker initiates a connection to a vulnerable application using Netty's `HAProxyMessageDecoder`.
2. The attacker sends a crafted PROXY protocol v2 binary header, specifically `0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A`.
3. The attacker then appends a malicious version byte, `0xFF`, immediately following the crafted binary prefix.
4. The `HAProxyMessageDecoder` attempts to perform protocol version detection by reading the 13th byte (the `0xFF`).
5. Due to Java's signed `byte` type and subsequent widening to `int` without proper masking, the `0xFF` byte is interpreted as `int -1` through sign extension.
6. This `int -1` value collides with the decoder's internal "need more data" sentinel value, causing the decoder to believe it requires more data to resolve the version.
7. The decoder enters an infinite loop, continuously requesting more data and never consuming the already received bytes, bypassing size limit enforcements.
8. All subsequent inbound network traffic is accumulated in an unbounded `cumulation` buffer, leading to the exhaustion of the JVM's direct memory allocation and a denial of service.

## Impact

The successful exploitation of CVE-2026-55851 leads to a complete denial of service (DoS) for applications using the vulnerable Netty `codec-haproxy` module. Attackers can trigger unbounded memory exhaustion in the target JVM by sending a specially crafted network payload. This will crash the affected service, making it unavailable to legitimate users. Organizations relying on these Netty versions for critical network services are at risk of service disruption and potential data loss if robust failover mechanisms are not in place. The attack requires no authentication and can be executed remotely, posing a significant threat to internet-facing applications.

## Recommendation

* Upgrade the `netty-codec-haproxy` module to a patched version immediately to remediate CVE-2026-55851. Specifically, upgrade `maven/io.netty:netty-codec-haproxy` to `4.2.16.Final` or later, or `4.1.136.Final` or later.
* Implement network intrusion detection/prevention systems (NIDS/NIPS) to monitor for unusual PROXY protocol traffic patterns that could indicate attempted exploitation of CVE-2026-55851.
* Ensure robust application monitoring is in place to detect sudden increases in direct memory usage or JVM crashes that could be indicative of an attack exploiting CVE-2026-55851.
