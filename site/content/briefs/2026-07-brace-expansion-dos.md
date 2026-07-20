---
title: 'CVE-2026-13149: brace-expansion Denial of Service Vulnerability'
slug: 2026-07-brace-expansion-dos
description: A Denial of Service vulnerability, tracked as CVE-2026-13149, exists in the `brace-expansion` JavaScript library (versions < 1.1.16, >= 2.0.0 < 2.1.2, and >= 3.0.0 < 5.0.7) that allows an attacker to cause exponential time complexity in the `expand()` function via crafted input, leading to a CPU hang and denial of service in Node.js applications.
date: "2026-07-20T20:53:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - javascript
  - npm
  - node.js
products:
  - brace-expansion (< 1.1.16)
  - brace-expansion (>= 2.0.0 < 2.1.2)
  - brace-expansion (>= 3.0.0 < 5.0.7)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Resource Development
    technique_id: T1499
    technique_name: Denial of Service
    evidence: A short, all-ASCII input (~90 bytes/30 groups) blocks the calling thread for minutes; a slightly longer input hangs it effectively indefinitely. Because the dominant consumers run on Node's single-threaded event loop, one small input can fully stall a worker/process.
    confidence_band: high
cves:
  - id: CVE-2026-13149
    epss: 0.00361
references:
  - https://github.com/advisories/GHSA-3jxr-9vmj-r5cp
  - CVE-2026-13149
---

A high-severity Denial of Service (DoS) vulnerability, identified as CVE-2026-13149, has been discovered in the `brace-expansion` JavaScript library, affecting versions prior to 1.1.16, versions from 2.0.0 up to but not including 2.1.2, and versions from 3.0.0 up to but not including 5.0.7. This flaw stems from an exponential-time complexity issue (O(2ⁿ)) within the `expand()` function when processing strings containing consecutive non-expanding brace groups, such as `a{},{},{},{}...`. An attacker can exploit this by providing a short, specially crafted ASCII input (e.g., ~90 bytes with 30 non-expanding groups), causing the application's CPU to hang for several minutes or even indefinitely. Since Node.js applications often rely on a single-threaded event loop, successful exploitation can lead to a complete denial of service for the affected worker or process, disrupting application availability.

## Attack Chain

1. An attacker crafts a malicious input string containing a series of consecutive non-expanding brace groups (e.g., `a{},{},{},{}...`).
2. This crafted string is delivered to a vulnerable application that utilizes the `brace-expansion` library (versions < 1.1.16, >= 2.0.0 < 2.1.2, or >= 3.0.0 < 5.0.7) to process user-controlled input.
3. The vulnerable application calls the `brace-expansion.expand()` function, passing the attacker-controlled string as an argument.
4. Within the `expand_` internal function of `brace-expansion`, the `post` variable is unconditionally computed recursively for each non-expanding group, even when it's not immediately used.
5. This recursive pattern, combined with a rewrite branch, results in an exponential increase in processing time (O(2ⁿ)) as the number of consecutive non-expanding groups in the input string grows.
6. For relatively small inputs (e.g., 30 non-expanding groups, approximately 90 bytes), the vulnerable process experiences extreme CPU utilization and a prolonged hang (minutes to indefinite).
7. In single-threaded environments, such as Node.js, this CPU hang leads to the entire application process becoming unresponsive, effectively causing a denial of service.

## Impact

Any application that directly or indirectly passes attacker-influenced strings to `brace-expansion.expand()` is susceptible to a denial of service. The vulnerability primarily impacts Node.js applications, which are single-threaded, allowing a small, maliciously crafted input (e.g., ~90 bytes) to cause a multi-minute or indefinite CPU hang. This effectively stalls the entire worker or process, preventing it from handling legitimate requests and rendering the service unavailable. For example, a 30-group input can block a thread for minutes, while a slightly longer input can cause an indefinite hang.

## Recommendation

* Upgrade the `brace-expansion` library to a patched version (>= 5.0.7) immediately to remediate CVE-2026-13149.
* If immediate upgrade is not possible, ensure that untrusted input is not passed directly to `brace-expansion.expand()` or functions that transitively use it (e.g., `minimatch`/`glob` brace patterns).
* Implement timeouts or run `brace-expansion` operations within separate worker threads/processes to isolate the impact of potential CPU hangs.
