---
title: yTree Stack-Based Buffer Overflow Vulnerability (CVE-2016-20038)
slug: 2026-03-ytree-buffer-overflow
description: yTree version 1.94-1.1 is vulnerable to a stack-based buffer overflow, allowing local attackers to execute arbitrary code by supplying an excessively long argument to overwrite the stack with shellcode.
date: "2026-03-28T12:15:59Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2016-20038
  - buffer-overflow
  - local-code-execution
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2016-20038
  - http://www.han.de/~werner/ytree.html
  - https://www.exploit-db.com/exploits/39406
  - https://www.vulncheck.com/advisories/ytree-stack-based-buffer-overflow
rules:
  - title: Detect Suspicious yTree CommandLine
    description: Detects suspicious command-line arguments passed to yTree, potentially indicating a buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Shellcode in yTree Command Line
    description: Detects potential shellcode in the command line of yTree, indicating exploitation attempt.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

yTree versions 1.94 to 1.1 are susceptible to a stack-based buffer overflow vulnerability (CVE-2016-20038). A local attacker can exploit this flaw by providing an overly long command-line argument to the application. The vulnerability allows the attacker to overwrite the stack memory, inject and execute arbitrary code within the context of the yTree application. This could lead to a full system compromise if the attacker gains sufficient privileges. This vulnerability has been publicly known…
