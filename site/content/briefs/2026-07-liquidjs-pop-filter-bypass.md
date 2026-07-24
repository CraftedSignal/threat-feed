---
title: LiquidJS pop Filter Bypasses Memory Limit Accounting
slug: 2026-07-liquidjs-pop-filter-bypass
description: A vulnerability (CVE-2026-55575) in the LiquidJS templating library's `pop` filter, affecting versions up to and including 10.27.0, allows an attacker to bypass the `memoryLimit` accounting, leading to uncontrolled memory allocation and potential denial of service when processing untrusted, large arrays in templates.
date: "2026-07-24T14:16:34Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - liquidjs
  - denial-of-service
  - vulnerability
  - memory-exhaustion
  - nodejs
products:
  - LiquidJS (<= 10.27.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: The identical `{{ huge | pop }}` does **not** throw — the allocation proceeds, and the only ceiling is the Node process's heap.
    confidence_band: high
cves:
  - id: CVE-2026-55575
    epss: 0.00384
references:
  - https://github.com/advisories/GHSA-g357-x5c3-c72p
---

A critical vulnerability, tracked as CVE-2026-55575, has been identified in the LiquidJS templating library, affecting all versions up to and including 10.27.0. The `pop` array filter, located at `src/filters/array.ts:91-95`, fails to properly account for memory allocations against the configured `memoryLimit` setting. Unlike its sibling array filters, `pop` creates an O(N) clone of an input array without deducting its size from the memory budget. This oversight allows an attacker to bypass the intended memory limits by crafting templates that apply the `| pop` filter to large, attacker-influenced arrays. Consequently, a single `render()` call can consume substantial amounts of memory, potentially leading to denial of service (DoS) through memory exhaustion. This is particularly dangerous in multi-tenant environments where `memoryLimit` is relied upon as a critical DoS guard against untrusted template inputs, such as those derived from user-generated content or large data sets. The vulnerability directly undermines the library's built-in resource protection mechanisms.

## Attack Chain

1. An attacker identifies a web application or service that utilizes the LiquidJS templating library, specifically versions up to and including 10.27.0.
2. The application allows attacker-influenced input, such as query parameters or API payloads, to be processed as a large array within a LiquidJS template context.
3. The attacker crafts a malicious template or injects template code that applies the `| pop` filter to this large, untrusted array (e.g., `{{ untrusted_array | pop }}`).
4. When the LiquidJS engine processes this template, the vulnerable `pop` filter creates a full O(N) clone of the large input array in memory.
5. Due to the vulnerability (CVE-2026-55575), this significant memory allocation is not accounted for against the application's configured `memoryLimit`.
6. The application continues to allocate memory unchecked, consuming Node.js process heap space.
7. This excessive memory consumption eventually leads to the exhaustion of the Node.js process's available memory or triggers a system-level Out-Of-Memory (OOM) killer.
8. The final objective is achieved: a denial of service for the affected LiquidJS application instance or the host system.

## Impact

The vulnerability renders the `memoryLimit` guard ineffective for templates utilizing the `pop` filter, allowing uncontrolled O(N) memory allocation when processing large, attacker-influenced arrays. This directly enables a denial of service (DoS) attack through memory exhaustion. A single template render can allocate hundreds of megabytes of array slots, circumventing the intended memory budget. In scenarios with concurrent requests, this effect is amplified, rapidly consuming the Node.js process heap and potentially leading to `oom-kill` events on the host system. This is a critical bypass of a documented DoS protection mechanism, especially concerning for multi-tenant applications that rely on `memoryLimit` to constrain resource usage from untrusted template inputs like search results, paginated lists, or user data.

## Recommendation

* Upgrade the `liquidjs` package to a version where CVE-2026-55575 has been resolved to mitigate this memory limit bypass.
* Review LiquidJS templates for any usage of the `| pop` filter on arrays derived from untrusted input; consider replacing it with guarded alternatives like `| slice: 0, arr.size | minus: 1`.
* Implement the provided workaround by registering a custom `pop` filter in LiquidJS that explicitly includes `this.context.memoryLimit.use(arr.length)` accounting for array allocations to re-establish the memory budget.
