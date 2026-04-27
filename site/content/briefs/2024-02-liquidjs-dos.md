---
title: LiquidJS replace_first Filter Exponential Memory Amplification DoS
slug: 2024-02-liquidjs-dos
description: The `replace_first` filter in LiquidJS is vulnerable to exponential memory amplification due to its use of JavaScript's `String.prototype.replace()` and mishandling of the `$&` backreference pattern, allowing attackers to bypass the `memoryLimit` and cause denial of service.
date: "2026-03-25T17:44:23Z"
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

LiquidJS version 10.24.0 and earlier contains a vulnerability in its `replace_first` filter that allows for exponential memory amplification. The `replace_first` filter delegates to JavaScript's native `String.prototype.replace()`, which interprets `$&` as a backreference to the matched substring. The filter only charges the input string length against the configured `memoryLimit`, not the amplified output. An attacker can exploit this by crafting a Liquid template with a replacement string…
