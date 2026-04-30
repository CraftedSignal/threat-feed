---
title: Zen C Compiler Stack-Based Buffer Overflow (CVE-2026-33491)
slug: 2026-03-zen-c-overflow
description: A stack-based buffer overflow vulnerability in Zen C compiler versions before 0.4.4 allows attackers to crash the compiler or potentially execute arbitrary code via a crafted `.zc` source file with overly long identifiers.
date: "2026-03-27T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve
  - buffer_overflow
  - compiler
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33491
  - https://github.com/zenc-lang/zenc/security/advisories/GHSA-rv74-w6q7-h8xr
rules:
  - title: Detect Suspicious Zen C Compilation
    description: Detects the execution of the Zen C compiler with potentially malicious .zc files as arguments.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Zen C Compiler Crash
    description: Detects Zen C compiler crashes by looking for specific error messages or abnormal process termination events.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Zen C is a systems programming language that compiles to human-readable GNU C/C11. Prior to version 0.4.4, a stack-based buffer overflow vulnerability (CVE-2026-33491) exists within the Zen C compiler. This flaw allows a malicious actor to craft a Zen C source file (`.zc`) containing excessively long struct, function, or trait identifiers. Successful exploitation of this vulnerability can lead to a compiler crash, causing disruption to development workflows, or potentially allow the attacker to…
