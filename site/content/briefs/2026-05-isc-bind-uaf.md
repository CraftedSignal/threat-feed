---
title: ISC BIND Use-After-Free Vulnerability Due to Race Condition (CVE-2026-5947)
slug: 2026-05-isc-bind-uaf
description: A race condition in ISC BIND can lead to a use-after-free vulnerability (CVE-2026-5947) when handling SIG(0) signed DNS messages, potentially leading to undefined behavior.
date: "2026-05-20T13:20:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - dns
  - use-after-free
  - denial-of-service
vendors:
  - ISC
products:
  - BIND 9 (9.20.0 - 9.20.22)
  - BIND 9 (9.21.0 - 9.21.21)
  - BIND 9 (9.20.9-S1 - 9.20.22-S1)
cves:
  - id: CVE-2026-5947
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5947
  - CVE-2026-5947
rules:
  - title: Detect SIG(0) validation failure
    description: Detects CVE-2026-5947 exploitation - Errors related to SIG(0) validation in DNS server logs.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.004
    data_sources:
      - dns_query
      - bind
  - title: Detect DNS Query Flood
    description: Detects high volume of DNS queries from a single source, indicative of a query flood.
    platform: sigma
    severity: low
    tactics:
      - denial_of_service
    techniques:
      - T1499.004
    data_sources:
      - dns_query
      - bind
rules_count: 2
---

A use-after-free vulnerability, tracked as CVE-2026-5947, exists in ISC BIND. Specifically, when BIND receives an incoming DNS message signed with SIG(0), it validates that signature. If the number of "recursive-clients" reaches the configured limit during this validation process due to a query flood, the DNS message may be discarded. However, a small window of time exists where the SIG(0) validation process might still attempt to read the now-discarded DNS message, leading to a use-after-free condition and undefined behavior. This issue affects BIND 9 versions 9.20.0 through 9.20.22, 9.21.0 through 9.21.21, and 9.20.9-S1 through 9.20.22-S1. BIND 9 versions 9.18.28 through 9.18.49 and 9.18.28-S1 through 9.18.49-S1 are not affected.

## Attack Chain

1. An attacker sends a DNS query flood to a BIND server to exhaust the `recursive-clients` limit.
2. Simultaneously, the attacker sends a crafted DNS message signed with SIG(0).
3. The BIND server receives the crafted DNS message and begins SIG(0) signature validation.
4. While the signature validation is in progress, the `recursive-clients` limit is reached due to the query flood.
5. The BIND server discards the DNS message to enforce the `recursive-clients` limit.
6. The SIG(0) validation routine attempts to read the discarded DNS message.
7. A use-after-free vulnerability is triggered because the memory associated with the DNS message has been freed.
8. This can lead to undefined behavior, potentially causing the BIND server to crash or, in more severe cases, allow for remote code execution.

## Impact

Successful exploitation of CVE-2026-5947 can cause a denial-of-service (DoS) condition on the affected BIND server, disrupting DNS resolution services. In a worst-case scenario, it could lead to remote code execution, potentially allowing an attacker to gain control of the server. Given the critical role of DNS servers in network infrastructure, this vulnerability poses a significant risk. While no specific victim counts are available, the widespread use of BIND makes many organizations vulnerable.

## Recommendation

*   Upgrade to a patched version of BIND 9 to address CVE-2026-5947. Versions 9.18.28 through 9.18.49 and 9.18.28-S1 through 9.18.49-S1 are not affected.
*   Monitor DNS server logs for errors related to SIG(0) validation, which may indicate exploitation attempts. Deploy the Sigma rule `Detect SIG(0) validation failure` to detect these events.
*   Rate limit incoming DNS queries to prevent query floods and reduce the likelihood of triggering the `recursive-clients` limit and the race condition.
