---
title: Denial of Service via Unbounded Expansion Length in Node.js brace-expansion Library (CVE-2026-14257)
slug: 2026-07-brace-expansion-dos
description: An attacker can exploit CVE-2026-14257, a denial of service vulnerability in the `brace-expansion` Node.js library, by crafting an input with deeply chained brace groups that causes the expanded string length to grow without bound, leading to an uncatchable out-of-memory process crash in any application processing untrusted input via `expand()` directly or through dependencies like `minimatch` or `glob`.
date: "2026-07-24T22:02:52Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - denial-of-service
  - vulnerability
  - node.js
  - software-supply-chain
products:
  - brace-expansion (<= 5.0.7)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: Any application that passes attacker-influenced strings to brace-expansion.expand() — directly, or transitively via minimatch / glob brace patterns — can be crashed by a small request. Because the failure is a fatal V8 out-of-memory error rather than a thrown exception, it cannot be caught and it takes down the whole worker/process, denying service.
    confidence_band: high
cves:
  - id: CVE-2026-14257
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-mh99-v99m-4gvg
---

A high-severity denial of service (DoS) vulnerability, tracked as CVE-2026-14257, exists in the Node.js `brace-expansion` library, affecting versions up to and including 5.0.7. The library's `expand()` function, which is used for generating string expansions from brace patterns, fails to properly bound the total length of the expanded strings despite having a limit on the number of results. Attackers can leverage this by crafting input with many chained brace groups, such as `'{a,b}'.repeat(N)`. This input causes each individual expanded result to grow in length with the number of groups, leading to excessive memory consumption. When processing even a relatively small input (~7.5 KB with `'{a,b}'.repeat(1500)`), the Node.js process exhausts its memory and crashes due to an uncatchable fatal out-of-memory error, resulting in a denial of service for the application. Applications directly using `brace-expansion` or indirectly through common dependencies like `minimatch` or `glob` are at risk.

## Attack Chain

1. An attacker crafts a malicious input string containing numerous chained brace groups (e.g., `'{a,b}'.repeat(1500)`).
2. The attacker delivers this crafted input to a vulnerable application that processes user-supplied strings.
3. The vulnerable application passes the crafted input string to the `brace-expansion.expand()` function, either directly or via a transitive dependency like `minimatch` or `glob`.
4. The `expand()` function begins processing the input, attempting to generate all possible expansions.
5. During expansion, `brace-expansion` generates intermediate and final string results where the individual string length grows linearly with the number of brace groups.
6. The `brace-expansion` process allocates and holds an increasing amount of memory for these growing strings and intermediate arrays.
7. The Node.js V8 engine exhausts its available heap memory as the total output size (`max` results * `N` character length) grows without bound.
8. The Node.js process terminates abruptly due to a fatal, uncatchable out-of-memory error, leading to a complete denial of service for the affected application.

## Impact

This vulnerability allows an attacker to cause a fatal denial of service for any Node.js application that processes untrusted or attacker-controlled strings through `brace-expansion.expand()`, either directly or indirectly via popular libraries such as `minimatch` or `glob`. The issue is critical because the out-of-memory error is uncatchable, meaning `try/catch` blocks around the `expand()` call will not prevent the process from crashing entirely. Even a small payload of approximately 7.5 KB is sufficient to crash a default Node.js process, leading to severe availability impacts for affected services. The vulnerability impacts application stability and reliability.

## Recommendation

* Upgrade the `brace-expansion` package to a patched release (version 5.0.8 or later) to remediate CVE-2026-14257.
* If immediate upgrade is not feasible, avoid passing untrusted input directly to `brace-expansion.expand()` or to components that use it (e.g., `minimatch`, `glob`).
* For applications that must process untrusted input, explicitly configure a small `max` and the new `maxLength` option when using `brace-expansion` to limit both the number and total length of expansions.
