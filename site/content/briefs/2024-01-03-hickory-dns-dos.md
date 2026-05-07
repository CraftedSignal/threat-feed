---
title: Hickory DNS NSEC3 Validation Vulnerability Leads to DoS
slug: 2024-01-03-hickory-dns-dos
description: A vulnerability in Hickory DNS's NSEC3 closest-encloser proof validation allows a remote attacker to cause a denial of service by exhausting memory when processing crafted DNS responses with mismatched SOA records.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - dnssec
  - memory-exhaustion
vendors:
  - Hickory DNS
products:
  - hickory-proto (0.25.0-alpha.3 to 0.25.2)
  - hickory-net (0.26.0-alpha.1 to 0.26.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-3v94-mw7p-v465
rules:
  - title: Hickory DNS Excessive Memory Allocation
    description: Detects processes that exhibit excessive memory allocation, which might indicate exploitation of the Hickory DNS vulnerability.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
  - title: Hickory DNS Debug Assertion Panic
    description: Detects panic messages from debug builds of Hickory DNS applications, potentially indicating exploitation attempts.
    platform: sigma
    severity: critical
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - application
      - linux
rules_count: 2
---

Hickory DNS is vulnerable to a denial-of-service (DoS) attack due to an unbounded loop in its NSEC3 closest-encloser proof validation. This affects `hickory-proto` versions 0.25.0-alpha.3 through 0.25.2 and `hickory-net` versions 0.26.0-alpha.1 through 0.26.0. The vulnerability resides within the `DnssecDnsHandle` component, specifically when built with the `dnssec-ring` or `dnssec-aws-lc-rs` feature and configured to perform DNSSEC validation. The issue occurs when validating NoData or NXDomain responses where the authority section contains a Start of Authority (SOA) record from a zone that is not an ancestor of the queried name (QNAME). An attacker who can return such a specially crafted response can trigger the unbounded loop, leading to excessive memory allocation and ultimately causing the process to crash or become unresponsive. The affected code was migrated from `hickory-proto` to `hickory-net` as part of the 0.26.0 release.

## Attack Chain

1. Attacker crafts a malicious DNS server or compromises an existing one.
2. The attacker configures the DNS server to respond to DNS queries with a specially crafted DNS response.
3. The crafted DNS response includes an SOA record in the authority section that is not an ancestor of the QNAME.
4. A vulnerable Hickory DNS resolver, recursor, or client initiates a DNS query that is routed to the malicious DNS server.
5. The vulnerable `DnssecDnsHandle` in Hickory DNS receives the crafted DNS response.
6. During NSEC3 closest-encloser proof validation, the code enters an unbounded loop.
7. The loop repeatedly calls `Name::base_name()` and pushes newly allocated `Name` and hashed-name entries into a candidate `Vec`, consuming memory.
8. The process exhausts available memory, resulting in a denial-of-service condition.

## Impact

Successful exploitation of this vulnerability can lead to a denial-of-service condition. Attackers can remotely crash debug builds of applications using the affected Hickory DNS versions, or exhaust memory in release builds. The number of victims depends on the number of applications using vulnerable versions of Hickory DNS and exposed to malicious DNS responses. This can affect any application using Hickory DNS for DNSSEC validation, including resolvers and clients.

## Recommendation

*   Upgrade to `hickory-net` version 0.26.1 to remediate the vulnerability. This is the recommended fix from Hickory DNS as stated in the overview.
*   Monitor memory usage of applications using `hickory-proto` (0.25.0-alpha.3 ... 0.25.2) and `hickory-net` (0.26.0-alpha.1 .. 0.26.0). An unusual increase in memory allocation could indicate an attempted exploitation.
