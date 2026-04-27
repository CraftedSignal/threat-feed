---
title: Picomatch ReDoS Vulnerability via Extglob Quantifiers
slug: 2026-04-picomatch-redos
description: Picomatch is vulnerable to Regular Expression Denial of Service (ReDoS) when processing crafted extglob patterns with quantifiers, leading to excessive CPU consumption and denial of service.
date: "2026-03-25T21:13:29Z"
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

The picomatch library is susceptible to a Regular Expression Denial of Service (ReDoS) attack when processing maliciously crafted extended glob (extglob) patterns. This vulnerability arises from inefficient regular expression generation when handling patterns that include extglob quantifiers like `+()` and `*()`, especially when these are combined with overlapping alternatives or nested extglobs. The flawed regex compilation can lead to catastrophic backtracking when processing non-matching…
