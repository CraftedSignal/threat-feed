---
title: Netty DNS Codec Input Validation Bypass Vulnerability
slug: 2024-01-03-netty-dns-bypass
description: Netty's DNS codec fails to enforce RFC 1035 domain name constraints, leading to potential DNS cache poisoning, denial-of-service, and domain validation bypass through null byte injection, overlength labels, silent truncation, and unbounded memory allocation.
date: "2026-05-07T00:12:47Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - netty
  - dns
  - vulnerability
  - cache-poisoning
vendors:
  - Netty
products:
  - Netty 4.2.12.Final
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Information Discovery
references:
  - https://github.com/advisories/GHSA-cm33-6792-r9fm
rules:
  - title: Detect Netty DNS Encoder Overlength Labels
    description: Detects the encoding of DNS labels exceeding the 63-byte limit, potentially indicating an attempt to exploit the Netty DNS encoder vulnerability.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - windows
  - title: Detect Java Process Spawning with DNS Decoder PoC
    description: Detects the execution of the DNS Decoder Length Bypass Proof-of-Concept (PoC) in java, which is used to test the decoder side of the vulnerability.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Netty, a widely used asynchronous event-driven network application framework, contains a critical input validation bypass vulnerability within its DNS codec (versions 4.2.12.Final and prior using `codec-dns`). The vulnerability stems from the `io.netty.handler.codec.dns.DnsCodecUtil` component, which inadequately validates domain name inputs during both encoding and decoding. This failure to adhere to RFC 1035 standards enables attackers to inject null bytes, create overlength labels, silently truncate domain names, and trigger unbounded memory allocation. Exploitation can lead to DNS cache poisoning, domain validation bypass, denial of service, and the generation of malformed DNS packets. This bidirectional attack surface allows for malicious DNS responses and user-influenced hostnames to be leveraged against applications using Netty's DNS resolution features.

## Attack Chain

1.  **Initial Input**: A Netty application receives a DNS query or is configured to resolve a domain name provided by a user, which may contain malicious elements such as null bytes or exceed length restrictions.
2.  **Encoding (Outbound)**: The application uses `DnsCodecUtil.encodeDomainName()` to encode the domain name into a DNS query packet without proper validation. This allows malicious domain names to be crafted.
3.  **DNS Query**: The crafted DNS query is sent to a DNS server. If the domain name contains null bytes, different DNS servers may interpret the domain differently, potentially leading to cache poisoning.
4.  **Decoding (Inbound)**: The application receives a DNS response containing a crafted domain name, potentially with oversized labels exceeding 63 bytes or the total 255-byte limit.
5.  **Vulnerable Decoding**: The `DnsCodecUtil.decodeDomainName()` method decodes the domain name without proper length validation, leading to unbounded StringBuilder growth if oversized labels are present.
6.  **Memory Exhaustion or Parser Confusion**: Excessive memory allocation occurs due to large labels, potentially causing a denial-of-service. Alternatively, overlength labels may be misinterpreted as compression pointers, causing parser confusion.
7.  **Cache Poisoning or Validation Bypass**: If null bytes are present, DNS cache poisoning or domain validation bypass may occur.
8.  **Application Impact**: Downstream processes that handle the decoded domain names (e.g., certificate validators, URL parsers) may crash or exhibit unexpected behavior due to the malformed domain names.

## Impact

Successful exploitation of this vulnerability can have severe consequences, including DNS cache poisoning, enabling attackers to redirect traffic to malicious servers. Domain validation bypass can allow attackers to impersonate legitimate domains. The unbounded memory allocation in the decoder can lead to denial-of-service conditions, impacting the availability of applications relying on Netty's DNS resolution. A single compromised application can lead to broader network disruptions through DNS poisoning.

## Recommendation

*   Upgrade to Netty version 4.2.13.Final or later, which addresses the input validation issues in the DNS codec.
*   Apply input validation on the client side to sanitize domain names before they are passed to the Netty DNS codec, mitigating encoder-side attacks.
*   Deploy the Sigma rule "Detect Netty DNS Encoder Overlength Labels" to identify instances of overlength labels being encoded in DNS queries.
*   Monitor and restrict outbound DNS traffic originating from applications using Netty to known, legitimate DNS resolvers to reduce the attack surface for encoder-side exploits.
*   Enable detailed logging of DNS queries and responses to facilitate forensic analysis in case of suspected DNS cache poisoning or other malicious activity.
