---
title: Hickory DNS Recursor Cache Poisoning via Sibling Zone Delegation
slug: 2024-11-hickory-dns-poisoning
description: The experimental `hickory-recursor` crate in Hickory DNS is vulnerable to cross-zone cache poisoning due to storing DNS records keyed by record name/type instead of query, enabling an attacker to redirect queries for a victim zone to an attacker-controlled nameserver.
date: "2026-04-30T18:10:58Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - dns
  - cache-poisoning
  - zone-delegation
vendors:
  - Palo Alto Networks
  - Hickory DNS
products:
  - hickory-recursor
  - hickory-resolver
references:
  - https://github.com/advisories/GHSA-83hf-93m4-rgwq
rules:
  - title: Detect NS Record Modification in DNS Responses
    description: Detects modifications to NS records within DNS responses, which could indicate a cache poisoning attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - dns_query
      - linux
  - title: Hickory DNS Recursion Enabled
    description: Detects when Hickory DNS is configured to act as a recursive resolver. This is an informational rule to identify systems at risk.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The Hickory DNS project's experimental `hickory-recursor` crate, now integrated into `hickory-resolver` under the `recursor` feature, contains a vulnerability in its DNS record cache (`DnsLru`). The cache stores records based on the record's name and type, rather than the originating query. This design flaw allows for cross-zone cache poisoning because the `cache_response()` function chains `ANSWER`, `AUTHORITY`, and `ADDITIONAL` sections into a single record iterator during insertion. The bailiwick filter uses the zone context of the NS pool that serviced the lookup, leading to improper validation of records from sibling zones. This issue affects all published versions of the experimental `hickory-recursor` crate prior to its integration into `hickory-resolver` 0.26.0. Users of the `hickory-dns` binary configured with the `recursor` feature are affected.

## Attack Chain

1.  Attacker registers the domain `attacker.poc.` and sets up a malicious nameserver.
2.  Hickory DNS server queries the nameserver for `attacker.poc.` to build its NS pool.
3.  The attacker's nameserver responds with an `AUTHORITY` section that includes a malicious record delegating a sibling zone, such as `victim.poc.`, to `ns.evil.poc.`.
4.  The Hickory DNS server's bailiwick check incorrectly validates the malicious `victim.poc. NS ns.evil.poc.` record because `victim.poc.` is a subdomain of the parent zone `poc.`.
5.  The malicious NS record for `victim.poc.` is stored in the cache, keyed by `(victim.poc., NS)`.
6.  A client queries the Hickory DNS server for a name within the `victim.poc.` zone.
7.  Hickory DNS server builds its NS pool for `victim.poc.` using the poisoned cache entry, directing queries to `ns.evil.poc.`.
8.  The attacker's nameserver now receives queries intended for the legitimate `victim.poc.` nameserver, allowing the attacker to intercept and manipulate DNS resolution.

## Impact

Successful exploitation of this vulnerability allows an attacker to redirect DNS queries for a target domain to an attacker-controlled nameserver. This can lead to various malicious activities, including phishing attacks, man-in-the-middle attacks, and the distribution of malware. The vulnerability affects any system using Hickory DNS with the `recursor` feature enabled, potentially impacting a wide range of users relying on the resolver for DNS resolution. If the targeted domain is critical for service delivery (e.g., email, web), the impact could be significant.

## Recommendation

*   Upgrade to `hickory-resolver` version 0.26.0 or later with the `recursor` feature enabled to address the vulnerability as described in the advisory ([https://github.com/advisories/GHSA-83hf-93m4-rgwq](https://github.com/advisories/GHSA-83hf-93m4-rgwq)).
*   If upgrading is not immediately feasible, disable the `recursor` feature in `hickory-dns` to prevent exploitation.
*   Implement monitoring for unexpected NS record changes, focusing on `AUTHORITY` sections of DNS responses, using a custom rule based on your environment and typical DNS configurations.
