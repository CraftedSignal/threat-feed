---
title: Immutable.js List 32-bit Trie Overflow Leads to Denial of Service
slug: 2026-07-immutable-js-dos
description: A vulnerability in Immutable.js List methods (`#set`, `#setSize`, `#setIn`, `#updateIn`) allows a remote, unauthenticated attacker to trigger an infinite loop or heap exhaustion by providing a crafted numeric string index in the range `[2 ** 30, 2 ** 31)`. This leads to an unrecoverable Denial of Service (DoS) by causing a tight CPU spin or process abortion, with an additional silent data corruption issue in `setSize`. This vulnerability impacts application availability but not confidentiality or integrity, and can be triggered by a single small HTTP request.
date: "2026-07-21T18:39:19Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:immutable-js:immutable:*:*:*:*:*:node.js:*:*
tags:
  - denial-of-service
  - vulnerability
  - javascript
  - npm
  - immutable-js
products:
  - Immutable.js < 4.3.9
  - Immutable.js >= 5.0.0-beta.1, < 5.1.8
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: The operation enters an uncatchable infinite loop (a tight CPU spin; a surrounding `try/catch` never regains control). Only killing the worker recovers it. On a populated `List` (...) heap exhaustion → the process aborts (`SIGABRT`, exit `134`, or kernel OOM-kill `137`).
    confidence_band: high
cves:
  - id: CVE-2026-59879
    cvss: 7.5
    epss: 0.0037
references:
  - https://github.com/advisories/GHSA-v56q-mh7h-f735
iocs:
  - type: package
    value: npm/immutable
  - type: package
    value: npm/immutable
ioc_counts:
  package: 2
---

A high-severity vulnerability (CVE-2026-59879) has been discovered in the `immutable.js` library, affecting versions `< 4.3.9` and `>= 5.0.0-beta.1, < 5.1.8`. This flaw allows a remote, unauthenticated attacker to cause a Denial of Service (DoS) in applications that use `immutable.js` by supplying specific numeric string inputs to `List#set`, `List#setSize`, `List#setIn`, or `List#updateIn` methods. Specifically, an index in the range `[2 ** 30, 2 ** 31)` can trigger an uncatchable infinite loop on an empty `List` (leading to a tight CPU spin) or unbounded memory allocation on a populated `List` (causing heap exhaustion and process abortion). The vulnerability is rooted in incorrect signed 32-bit bitwise arithmetic handling within `setListBounds()` and can be triggered via a single, small HTTP request body, URL parameter, or key-path, impacting application availability. Additionally, a companion silent data corruption issue in `setSize` can lead to incorrect application state.

## Attack Chain

1. An unauthenticated attacker crafts a small HTTP request, embedding a numeric string (e.g., `1073741824`) in the range `[2 ** 30, 2 ** 31)` into a request body, URL, or key-path.
2. The vulnerable application, using `immutable.js` versions `< 4.3.9` or `>= 5.0.0-beta.1, < 5.1.8`, receives this request.
3. The application processes the untrusted input, passing the crafted numeric string as an index to `List#set`, `List#setSize`, `List#setIn`, or `List#updateIn`.
4. Within `immutable.js`, the `setListBounds()` function attempts to handle the index using signed 32-bit bitwise arithmetic.
5. Due to a bug where JavaScript's shift count is taken modulo 32, the level-raising loop condition `newTailOffset >= 1 << (newLevel + SHIFT)` becomes perpetually true.
6. If the `List` is empty, this results in an uncatchable infinite CPU spin, freezing the worker process.
7. If the `List` is populated (e.g., from an array with >= 32 elements), each iteration of the loop allocates a new `VNode` without bound, rapidly exhausting the process heap.
8. Heap exhaustion leads to the application process aborting (e.g., `SIGABRT`, exit `134`, or kernel OOM-kill `137`), causing a Denial of Service.
9. Alternatively, if `setSize` is called with a large value like `2 ** 31` or `2 ** 32 + 5`, silent wraparound due to `ToInt32` coercion can corrupt the `List`'s size to 0 or 5 respectively, leading to data corruption without crashing.

## Impact

This vulnerability primarily impacts the availability of applications using vulnerable versions of `immutable.js`. A single, small, unauthenticated HTTP request can trigger an unrecoverable Denial of Service (DoS) by either causing a worker process to enter an infinite CPU spin, effectively hanging, or by forcing the process to consume all available memory, leading to an application crash (e.g., `SIGABRT` or OOM-kill). This can affect common application patterns such as configuration stores, document/collection editors, Redux-Immutable reducers, or JSON-Patch endpoints that route untrusted input into `List` operations. There is no observed impact on confidentiality or integrity, nor does it lead to Remote Code Execution (RCE). The companion silent data corruption issue can lead to applications operating with incorrect state, potentially causing further malfunctions, but without an immediate crash.

## Recommendation

* **Upgrade immutable.js:** Immediately upgrade `immutable.js` to version `4.3.9` or higher, or to `5.1.8` or higher for the v5 beta releases, to remediate CVE-2026-59879.
* **Implement Input Validation:** For systems that cannot be immediately upgraded, validate and clamp any externally supplied `List` index or `setIn`/`updateIn` key-path segments. Reject numeric path segments greater than or equal to `2 ** 30` before passing them to `immutable.js` methods.
* **Containerize and Resource Limit Applications:** Run request handling processes in isolated worker environments with resource limits (e.g., cap heap size using `--max-old-space-size`) to contain any potential process aborts, allowing for faster recovery or restart of affected workers.
