---
title: Algorithmic Complexity DoS in @chenglou/pretext
slug: 2024-05-pretext-dos
description: A denial-of-service vulnerability exists in the `isRepeatedSingleCharRun()` function of the `@chenglou/pretext` npm package (versions 0.0.4 and earlier), which exhibits O(n²) algorithmic complexity when processing input consisting of repeated identical punctuation characters, leading to main thread blocking and DoS.
date: "2024-05-02T17:21:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - denial-of-service
  - algorithmic-complexity
  - pretext
vendors:
  - chenglou
products:
  - pretext
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-5478-66c3-rhxr
rules:
  - title: Detect Long Running Node.js Process
    description: Detects Node.js processes running for unusually long durations, which might indicate exploitation of the algorithmic complexity vulnerability in @chenglou/pretext.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499
    data_sources:
      - process_creation
      - windows
  - title: Detect Long Running Node.js Process Linux
    description: Detects Node.js processes running for unusually long durations, which might indicate exploitation of the algorithmic complexity vulnerability in @chenglou/pretext on Linux
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The `@chenglou/pretext` npm package, version 0.0.4 and earlier, is vulnerable to a denial-of-service attack due to inefficient algorithmic complexity in the `isRepeatedSingleCharRun()` function. This function, located in `src/analysis.ts`, rescans the entire accumulated segment on every merge iteration during text analysis. This results in O(n²) total work for input consisting of repeated identical punctuation characters. An attacker who controls text passed to the `prepare()` function can exploit this vulnerability to block the main thread for a significant amount of time. For example, an 80KB input string consisting of repeated parenthesis characters (e.g., `"(".repeat(80_000)`) can block the main thread for approximately 20 seconds on Node.js v24.12.0 running on Windows x64. This issue was identified in commit 9364741d3562fcc65aacc50953e867a5cb9fdb23 (v0.0.4).

## Attack Chain

1. An attacker crafts a text string containing a large number of repeated, identical punctuation characters such as `(`, `[`, `{`, `#`, `@`, `!`, `%`, `^`, `~`, `<`, or `>`.
2. The attacker submits the crafted text string to an application that uses the `@chenglou/pretext` library. The text could be sent as a message in a chat application, submitted in a comment form, or used in server-side rendering.
3. The application's code calls the `prepare()` function from the `@chenglou/pretext` library to perform layout measurement on the attacker-controlled text. This happens in `layout.ts` at line 472.
4. The `prepare()` function internally calls `prepareInternal()` in `layout.ts` (line 424), which then invokes `analyzeText()` at line 430.
5. `analyzeText()` calls the `buildMergedSegmentation()` function (analysis.ts:1013 -> analysis.ts:795) to process the text. This function uses `Intl.Segmenter` to break the text into segments.
6. For each segment identified by `Intl.Segmenter`, the `buildMergedSegmentation()` function iterates through the segments, checking if consecutive non-word-like segments consist of the same single character. When it finds matching segments, it merges them.
7. During the merge process, the `isRepeatedSingleCharRun()` function is called (analysis.ts:857 -> analysis.ts:285) to verify that all characters in the accumulated segment match the character being merged.
8. The `isRepeatedSingleCharRun()` function iterates over the entire accumulated string (O(n) operation) for each merge, resulting in O(n²) complexity for large inputs. This causes the main thread to block. The final objective is to cause denial of service on the client or server processing the text.

## Impact

This vulnerability allows an attacker to cause a denial-of-service (DoS) condition.
Specifically, chat/messaging applications, comment/form systems, or server-side rendering processes that use `@chenglou/pretext` can be targeted. A single crafted message or input (e.g., 80KB of repeated parenthesis characters) can block the main thread for approximately 20 seconds. In server-side rendering scenarios (Node.js/Bun), a single malicious request can consume excessive CPU time (20+ seconds per 80KB of payload). This can lead to a complete outage of the affected service.

## Recommendation

*   Limit the length of text passed to the `prepare()` function to mitigate the impact of this vulnerability before a patch is available.
*   Monitor CPU usage for processes utilizing the `@chenglou/pretext` library for unusually long execution times that could indicate exploitation of this vulnerability.
*   Deploy the Sigma rule that detects potential exploitation attempts based on excessive process execution time.
*   Upgrade to a patched version of `@chenglou/pretext` once it becomes available.
