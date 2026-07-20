---
title: Mistune Quadratic-Time Parsing Vulnerability in Formatting Plugins
slug: 2026-07-mistune-quadratic-redos
description: The mistune Python library, when used with the 'strikethrough', 'mark', or 'insert' plugins enabled, is vulnerable to an algorithmic-complexity denial-of-service (DoS) attack where an attacker can send specially crafted markdown input causing quadratic parsing time, leading to high CPU utilization and potential service outages.
date: "2026-07-20T21:35:48Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:mistune_project:mistune:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - re-dos
  - python
  - library-vulnerability
vendors:
  - mistune
products:
  - mistune (< 3.3.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Denial of Service
    technique_id: T1499
    technique_name: Resource Exhaustion
    evidence: An 8 KB input pegs the CPU for ~4 seconds; 16 KB → ~17 seconds. Repeating the request floods the worker pool. On a single-thread WSGI handler this is one request per outage; on a thread pool, a small number of concurrent attackers exhausts capacity.
    confidence_band: high
cves:
  - id: CVE-2026-59922
    cvss: 7.5
    epss: 0.00366
references:
  - https://github.com/advisories/GHSA-c8j7-8cv4-2xmq
---

The mistune Python markdown parser library is susceptible to an algorithmic-complexity denial-of-service (DoS) vulnerability, tracked as CVE-2026-59922, when specific formatting plugins are enabled. This vulnerability impacts versions of mistune prior to 3.3.0. Attackers can exploit this by submitting specially crafted markdown input containing long, repeated sequences of `~~x~~`, `==x==`, or `^^x^^` markers, which are used for strikethrough, mark, and insert formatting respectively. The parsing process for these inputs exhibits quadratic time complexity (O(N²)), meaning the CPU time required quadruples when the input size doubles. This can cause applications using mistune to parse user-supplied markdown to experience severe CPU exhaustion, leading to significant performance degradation or complete service outages. While the affected plugins are not enabled by default, they are commonly activated in applications requiring GitHub-flavored Markdown or similar extensions.

## Attack Chain

1. An attacker identifies an application using the `mistune` library to render user-supplied markdown content.
2. The application has one or more of the `strikethrough`, `mark`, or `insert` plugins enabled (e.g., `plugins=['strikethrough']`).
3. The attacker crafts a markdown payload, such as `~~x~~` repeated 8000 times (approximately 8 KB in size). Analogous payloads use `==x==` or `^^x^^`.
4. The attacker submits this specially crafted markdown payload to the vulnerable application.
5. The application invokes `mistune.create_markdown(...)(payload)` to process the input.
6. Due to the quadratic-time parsing logic for these specific markers, the application's CPU becomes heavily utilized; an 8 KB payload can peg the CPU for approximately 4 seconds, while a 16 KB payload extends this to about 17 seconds.
7. Repeated requests with such payloads can exhaust the application's worker pool, leading to a denial of service for legitimate users.

## Impact

Successful exploitation of CVE-2026-59922 results in a denial-of-service condition for applications relying on the mistune library with affected plugins. The primary impact is severe CPU exhaustion on the server, which can lead to application unresponsiveness, slow processing of legitimate requests, or complete service outages. An 8 KB malicious input can consume a single CPU core for roughly 4 seconds, while a 16 KB input extends this to 17 seconds, and 32 KB to 70 seconds. This predictable quadratic scaling means that even small, unauthenticated requests can significantly degrade or halt service, particularly in single-threaded environments or when attacker requests overwhelm thread pools. There is no significant memory growth observed, but the pure CPU cost can effectively render the application unusable.

## Recommendation

* Upgrade the `mistune` Python package to version 3.3.0 or later to patch CVE-2026-59922, as described in the affected_products section.
* If immediate patching is not possible, review application configurations to determine if the `strikethrough`, `mark`, or `insert` plugins are enabled. Consider disabling these plugins if they are not critical for your application's functionality.
