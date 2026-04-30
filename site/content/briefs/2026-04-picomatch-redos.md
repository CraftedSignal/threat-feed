---
title: Picomatch ReDoS Vulnerability via Extglob Quantifiers
slug: 2026-04-picomatch-redos
description: Picomatch is vulnerable to Regular Expression Denial of Service (ReDoS) when processing crafted extglob patterns with quantifiers, leading to excessive CPU consumption and denial of service.
date: "2026-03-25T21:13:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - picomatch
  - ReDoS
  - denial-of-service
  - extglob
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-c2c7-rcm5-vvqj
rules:
  - title: Detect Excessive CPU Usage by Node.js Process
    description: Detects excessive CPU usage by a Node.js process, which could be indicative of a ReDoS attack via picomatch.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - process_usage
      - linux
  - title: Detect Compilation of Suspicious Picomatch Extglob Patterns
    description: Detects the compilation of potentially malicious picomatch extglob patterns within a Node.js application, indicating potential ReDoS exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The picomatch library is susceptible to a Regular Expression Denial of Service (ReDoS) attack when processing maliciously crafted extended glob (extglob) patterns. This vulnerability arises from inefficient regular expression generation when handling patterns that include extglob quantifiers like `+()` and `*()`, especially when these are combined with overlapping alternatives or nested extglobs. The flawed regex compilation can lead to catastrophic backtracking when processing non-matching input strings. Problematic patterns include examples like `+(a|aa)`, `+(*|?)`, `+(+(a))`, `*(+(a))`, and `+(+(+(a)))`. The issue affects picomatch versions before 4.0.4, 3.0.2, and 2.3.2. Applications that permit untrusted users to supply glob patterns to picomatch are at risk, potentially causing a denial-of-service condition due to excessive CPU usage and event loop blocking.

## Attack Chain

1. An attacker identifies an application that utilizes the picomatch library to process user-supplied glob patterns.
2. The attacker crafts a malicious glob pattern containing nested extglobs or extglob quantifiers such as `+(a|aa)` or `+(+(a))`.
3. The attacker submits the malicious glob pattern to the vulnerable application.
4. The application passes the attacker-supplied glob pattern to the `picomatch` library for compilation or matching.
5. Picomatch compiles the malicious glob pattern into an inefficient regular expression.
6. When matching the compiled regex against an input string, catastrophic backtracking occurs due to the regex complexity.
7. CPU consumption spikes as the regex engine struggles to process the input, blocking the Node.js event loop.
8. The application becomes unresponsive, leading to a denial-of-service condition.

## Impact

Successful exploitation of this ReDoS vulnerability in picomatch can lead to significant denial-of-service conditions. While the number of affected applications is unknown, any application utilizing picomatch to process untrusted glob patterns is potentially vulnerable. The impact includes excessive CPU consumption, event loop blocking in Node.js applications, and potential service outages, causing disruption and impacting availability. Local testing has shown multi-second delays with short inputs, demonstrating the severity of the issue.

## Recommendation

*   Upgrade to picomatch version 4.0.4, 3.0.2, or 2.3.2, or a later version depending on the supported release line to patch CVE-2026-33671.
*   Implement input validation on any endpoint that accepts glob patterns to reject or sanitize patterns containing nested extglobs or extglob quantifiers such as `+()` and `*()` as described in the overview.
*   Disable extglob support for untrusted patterns by using `noextglob: true` as mentioned in the workarounds section.
