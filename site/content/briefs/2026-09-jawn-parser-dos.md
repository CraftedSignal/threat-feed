---
title: Jawn AsyncParser Denial of Service via Quadratic Parsing Complexity
slug: 2026-09-jawn-parser-dos
description: The jawn-parser library is vulnerable to a denial-of-service condition where fragmented input triggers quadratic parsing effort, leading to CPU exhaustion.
date: "2026-09-24T01:57:57Z"
lastmod: "2026-09-24T01:58:04Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:typelevel:jawn-parser:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - library-vulnerability
  - jvm
vendors:
  - Typelevel
products:
  - jawn-parser (<= 1.6.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: AsyncParser can be forced to perform O(n^2) work on the length of the input.
    confidence_band: high
cves:
  - id: CVE-2026-61814
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-w4cm-gvhj-cgw6
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61814
  - https://github.com/advisories/GHSA-cc4v-rvgp-2pf3
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  mitigation_plan:
    - priority: immediate
      action: Upgrade jawn-parser to version 1.7.0 or later
      owner: IT Operations
      addresses: CVE-2026-61814
      evidence: Fixed in jawn-parser-1.7.0.
updates:
  - at: "2026-09-24T01:58:04Z"
    level: L1
    summary: added coverage for jawn-parser (<= 1.6.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-cc4v-rvgp-2pf3
---

The jawn-parser library contains a vulnerability (CVE-2026-61814) in its `AsyncParser` component that allows for a denial-of-service (DoS) attack through CPU exhaustion. When the parser processes JSON tokens delivered in small, fragmented chunks, it performs redundant rescanning of the incomplete token during each `absorb` call. This quadratic complexity (O(n^2)) on the input length allows an attacker who can influence the size and delivery frequency of JSON chunks to force the application to consume excessive CPU resources. This affects users of `jawn-parser` versions 1.6.0 and earlier across Scala versions 2.12, 2.13, and 3. Defenders should prioritize upgrading to version 1.7.0 or switching to the synchronous `Parser` implementation if an immediate upgrade is not feasible.

## Impact

Successful exploitation results in high CPU utilization, which can lead to service degradation or complete denial of service for applications processing untrusted JSON streams. This vulnerability impacts systems utilizing `jawn-parser` for high-throughput or internet-facing data ingestion where attackers can control the byte-level fragmentation of incoming JSON payloads.

## Recommendation

- Upgrade `jawn-parser` to version 1.7.0 or later to include the fix for CVE-2026-61814.
- For systems unable to upgrade, implement input buffering to ensure large chunks are provided to the `absorb` method, mitigating the repeated rescanning overhead.
- Migrate to the synchronous `Parser` class for sensitive ingestion points where fragmentation control cannot be guaranteed.
