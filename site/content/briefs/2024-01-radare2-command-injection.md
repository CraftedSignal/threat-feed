---
title: radare2 PDB Parser Command Injection Vulnerability (CVE-2026-40517)
slug: 2024-01-radare2-command-injection
description: A command injection vulnerability exists in radare2 versions prior to 6.1.4, where a crafted PDB file with newline characters in symbol names can inject arbitrary radare2 commands, leading to arbitrary OS command execution.
date: "2024-01-24T12:00:00Z"
severities:
  - high
tags:
  - command-injection
  - radare2
  - CVE-2026-40517
vendors:
  - radare
products:
  - radare2
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-40517
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40517
rules:
  - title: Detect Suspicious Radare2 Process Execution
    description: Detects suspicious radare2 process execution, potentially indicating command injection attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Radare2 Process Execution Linux
    description: Detects suspicious radare2 process execution on Linux, potentially indicating command injection attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A command injection vulnerability, identified as CVE-2026-40517, affects radare2 versions prior to 6.1.4. This flaw resides within the PDB parser's `print_gvars()` function. An attacker can exploit this vulnerability by creating a malicious PDB file containing newline characters within symbol names. These newline characters enable the injection of arbitrary radare2 commands, which are then executed due to unsanitized symbol name interpolation. This interpolation occurs during the execution of…
