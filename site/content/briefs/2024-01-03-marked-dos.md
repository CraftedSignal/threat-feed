---
title: Denial of Service Vulnerability in marked via Infinite Recursion
slug: 2024-01-03-marked-dos
description: A denial of service vulnerability exists in marked version 18.0.0 due to infinite recursion when processing a specific 3-byte sequence (tab, vertical tab, and newline), leading to unbounded memory allocation and application crash.
date: "2024-01-03T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - denial-of-service
  - javascript
  - marked
  - vulnerability
vendors:
  - npm
products:
  - marked
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-6v9c-7cg6-27q7
rules:
  - title: Detect Node.js Process Crash Due to Memory Exhaustion (marked)
    description: Detects Node.js processes crashing with a memory exhaustion error, potentially indicating exploitation of the marked DoS vulnerability.
    platform: sigma
    severity: high
    tactics:
      - availability
      - defense_evasion
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - windows
  - title: Detect Node.js Process Crash Due to Memory Exhaustion (marked) - Linux
    description: Detects Node.js processes crashing with a memory exhaustion error, potentially indicating exploitation of the marked DoS vulnerability on Linux.
    platform: sigma
    severity: high
    tactics:
      - availability
      - defense_evasion
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical Denial of Service (DoS) vulnerability has been identified in `marked@18.0.0`. This vulnerability arises from the processing of a specific 3-byte input sequence: a tab character, a vertical tab character, and a newline character (`\x09\x0b\n`). An unauthenticated attacker can exploit this by sending this sequence to a Node.js application utilizing the vulnerable version of the `marked` library. This input triggers an infinite recursion loop within the `marked` tokenizer during parsing, leading to unbounded memory allocation and ultimately causing the host Node.js application to crash due to Memory Exhaustion (OOM). This vulnerability allows for a total loss of availability for any application using the vulnerable library to process potentially untrusted input.

## Attack Chain

1.  The attacker sends a crafted input string containing the sequence `\x09\x0b\n` to a Node.js application using `marked@18.0.0`.
2.  The `space()` tokenizer in `marked` consumes the initial tab character (`\x09`) using the regex `/^(?:[ \t]*(?:\n|$))+/`.
3.  The newline block rule fails to match the remaining `\x0b\n` sequence because the vertical tab is not accounted for in the rule `[ \t]`.
4.  The parser falls through to the `text` tokenizer (`/^[^\n]+/`), which matches the `\x0b\n` sequence.
5.  Inside the `blockTokens()` function, the `text` tokenizer creates a text token.
6.  The `blockTokens()` function then calls `inlineTokens()` on the same input (`\x0b\n`).
7.  The `inlineTokens()` function's text rule matches `\x0b\n` and recursively calls `inlineTokens()` again, leading to an infinite loop.
8.  Each recursive call allocates new token objects and concatenates strings, causing memory usage to grow until the Node.js heap limit is reached, resulting in a crash.

## Impact

This vulnerability results in a High-Severity Denial of Service (DoS) via Memory Exhaustion. Any application, API, chatbot, or documentation system using `marked@18.0.0` to parse untrusted user input is vulnerable. The attack requires minimal resources from the attacker, only the ability to send a 3-byte payload, to cause a total loss of availability. The vulnerability affects `npm/marked` versions greater than or equal to 18.0.0 and less than or equal to 18.0.1.

## Recommendation

*   Upgrade to a patched version of the `marked` library that addresses the infinite recursion vulnerability.
*   Monitor Node.js application logs for error messages indicating memory exhaustion or crashes, which might indicate exploitation attempts.
*   Implement input validation to sanitize or reject input containing the malicious `\x09\x0b\n` sequence.
*   Deploy the Sigma rule for `marked` process crashes due to memory exhaustion to identify exploitation attempts.
