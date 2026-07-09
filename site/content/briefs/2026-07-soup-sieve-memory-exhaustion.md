---
title: Soup Sieve Memory Exhaustion via Large Comma-Separated Selector Lists (CVE-2026-49476)
slug: 2026-07-soup-sieve-memory-exhaustion
description: A memory exhaustion vulnerability (CVE-2026-49476) in the soupsieve CSS selector parser, an indirect dependency of Beautiful Soup 4, allows an unauthenticated attacker to cause a denial of service by supplying a crafted, large comma-separated CSS selector string to applications using `soupsieve.compile()` or Beautiful Soup's `.select()`/`.select_one()`, leading to unbounded memory allocation and system resource exhaustion.
date: "2026-07-09T13:38:51Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - memory-exhaustion
  - python
  - supply-chain
vendors:
  - Soupsieve Project
  - Beautiful Soup Project
products:
  - soupsieve <= 2.8.3
  - beautifulsoup4
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: An attacker who can supply a crafted CSS selector string to `soupsieve.compile()` or Beautiful Soup's `.select()` / `.select_one()` can cause the application to allocate hundreds of megabytes of heap memory from a relatively small input, leading to memory exhaustion and denial of service.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-2wc2-fm75-p42x
---

A critical memory exhaustion vulnerability, tracked as CVE-2026-49476, has been identified in soupsieve versions up to and including 2.8.3. Soupsieve is a CSS selector engine widely used by `beautifulsoup4`, a popular Python library for parsing HTML and XML documents. This vulnerability allows an unauthenticated attacker to trigger a denial of service (DoS) by providing a specially crafted, large comma-separated CSS selector string to applications that process user-supplied selectors through `soupsieve.compile()` or Beautiful Soup's `.select()`/`.select_one()`. A relatively small input of 500 KB can lead to approximately 244 MB of heap memory allocation, representing a 488x amplification ratio. This can result in out-of-memory (OOM) kills in containerized environments, severe performance degradation due to swap thrashing on bare-metal systems, or Python `MemoryError` exceptions, affecting any server-side Python application accepting external CSS selectors.

## Attack Chain

1. An attacker crafts a large CSS selector string containing numerous comma-separated items, such as "a,a,a,..." with hundreds of thousands of repetitions.
2. The attacker delivers this crafted selector string to a vulnerable Python application that incorporates `soupsieve` or `beautifulsoup4` and processes user-supplied CSS selectors.
3. The application passes the malicious string to `soupsieve.compile()` or to Beautiful Soup's `.select()` or `.select_one()` methods.
4. The `soupsieve` parser tokenizes the entire string and identifies each comma-delimited segment of the selector list.
5. For each segment, `soupsieve` attempts to parse it into a `Selector` object, including associated tag, attribute, and pseudo-class metadata.
6. All parsed `Selector` objects are stored in a `SelectorList` structure.
7. Due to the unbounded parsing, each `Selector` object consumes approximately 976 bytes of heap memory, leading to a linear increase in memory consumption for each item in the comma-separated list.
8. This massive, unintended memory allocation exhausts available system resources, resulting in a denial of service for the target application.

## Impact

This vulnerability poses a high risk of denial of service (DoS) for any server-side Python application that processes user-supplied CSS selectors using `soupsieve` (versions <= 2.8.3) or `beautifulsoup4`. Successful exploitation can cause severe operational disruptions, including OOM kills in containerized deployments (such as Kubernetes or Docker containers), leading to application crashes and unavailability. On bare-metal servers, the intense memory demands can trigger swap thrashing, significantly degrading overall system performance for all co-located processes. In other cases, Python's `MemoryError` exception will terminate the affected process. The attack's scalability is linear, meaning an attacker can precisely tune the input payload to exhaust a target's specific memory limits, and concurrent requests can multiply the effect.

## Recommendation

* **Patch `soupsieve`**: Immediately upgrade `soupsieve` to a patched version greater than 2.8.3 to remediate CVE-2026-49476.
* **Upgrade `beautifulsoup4`**: Ensure `beautifulsoup4` is updated to a version that bundles a patched `soupsieve` dependency, or explicitly update `soupsieve` in your project's dependency lock file.
* **Input validation**: Implement strict input validation and sanitization for any user-supplied CSS selectors, limiting their complexity and length before processing them with `soupsieve.compile()` or Beautiful Soup's `.select()`/`.select_one()`.
* **Resource Monitoring**: Deploy robust memory and CPU utilization monitoring for Python applications that process untrusted input, using tools like `tracemalloc` for deep memory profiling if custom application logging is enabled.
