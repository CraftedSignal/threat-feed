---
title: LiquidJS replace_first Filter Exponential Memory Amplification DoS
slug: 2024-02-liquidjs-dos
description: The `replace_first` filter in LiquidJS is vulnerable to exponential memory amplification due to its use of JavaScript's `String.prototype.replace()` and mishandling of the `$&` backreference pattern, allowing attackers to bypass the `memoryLimit` and cause denial of service.
date: "2026-03-25T17:44:23Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - liquidjs
  - denial-of-service
  - memory-amplification
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
references:
  - https://github.com/advisories/GHSA-6q5m-63h6-5x4v
rules:
  - title: Detect LiquidJS replace_first Memory Amplification Attempt
    description: Detects suspicious HTTP requests that attempt to exploit the LiquidJS replace_first memory amplification vulnerability by looking for multiple $& sequences in the template data.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.002
    data_sources:
      - webserver
      - linux
  - title: Detect LiquidJS replace_first with large number of $& repetitions
    description: Detects HTTP requests with LiquidJS templates using replace_first filter and a large number of $& repetitions, indicating a potential memory amplification attack.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

LiquidJS version 10.24.0 and earlier contains a vulnerability in its `replace_first` filter that allows for exponential memory amplification. The `replace_first` filter delegates to JavaScript's native `String.prototype.replace()`, which interprets `$&` as a backreference to the matched substring. The filter only charges the input string length against the configured `memoryLimit`, not the amplified output. An attacker can exploit this by crafting a Liquid template with a replacement string containing multiple repetitions of `$&`, causing the output string to grow exponentially with each replacement. By chaining this technique across multiple variable assignments, an attacker can easily exhaust available memory, leading to a denial-of-service condition. This vulnerability affects applications that render user-provided Liquid templates, such as CMS platforms, newsletter editors, and SaaS platforms.

## Attack Chain

1.  The attacker crafts a malicious Liquid template.
2.  The template uses the `replace_first` filter with a pattern containing multiple `$&` backreferences. For example: `{% assign s = "A" %}{% assign s = s | replace_first: s, "$&$&$&...(50 times)...$&" %}`.
3.  The LiquidJS engine parses the template.
4.  The `replace_first` filter is called.
5.  The filter utilizes the native `String.prototype.replace()` method to perform the replacement.
6.  Each instance of `$&` in the replacement string is expanded to the matched substring, causing the output string to grow exponentially.
7.  The expanded string consumes excessive memory, potentially exceeding available resources.
8.  The application crashes or becomes unresponsive, resulting in a denial-of-service condition.

## Impact

Successful exploitation of this vulnerability can lead to a denial-of-service condition. A single request can allocate hundreds of megabytes of memory, and concurrent requests can cause complete service unavailability. The Node.js event loop is blocked, and legitimate user requests are stalled. Empirical results have demonstrated that with 20 concurrent requests, legitimate users experience up to 13-second delays. Each attack request costs only a few hundred bytes, making it easy to launch a large-scale attack.

## Recommendation

*   Apply a patch to LiquidJS that properly accounts for memory usage when using the `replace_first` filter with backreferences.
*   Alternatively, disable or remove the `replace_first` filter entirely and use the `replace` filter instead, which treats `$&` as a literal string.
*   Implement input validation and sanitization to prevent the use of `$&` backreferences in user-provided Liquid templates.
*   Monitor web server logs for suspicious requests containing Liquid templates with excessive use of the `replace_first` filter and `$&` patterns using the Sigma rule below.
*   Implement rate limiting to mitigate the impact of denial-of-service attacks.
*   Increase the `memoryLimit` configuration value to provide a temporary buffer against memory exhaustion, but this will not fully prevent the attack.
