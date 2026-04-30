---
title: radare2 PDB Parser Command Injection Vulnerability (CVE-2026-40517)
slug: 2024-01-radare2-command-injection
description: A command injection vulnerability exists in radare2 versions prior to 6.1.4, where a crafted PDB file with newline characters in symbol names can inject arbitrary radare2 commands, leading to arbitrary OS command execution.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
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

A command injection vulnerability, identified as CVE-2026-40517, affects radare2 versions prior to 6.1.4. This flaw resides within the PDB parser's `print_gvars()` function. An attacker can exploit this vulnerability by creating a malicious PDB file containing newline characters within symbol names. These newline characters enable the injection of arbitrary radare2 commands, which are then executed due to unsanitized symbol name interpolation. This interpolation occurs during the execution of the `idp` command against the malicious PDB file. Successful exploitation allows the attacker to achieve arbitrary OS command execution through radare2's shell execution operator, posing a significant risk to systems where radare2 is used for binary analysis.

## Attack Chain

1.  Attacker crafts a malicious PDB file. This file contains newline characters embedded within symbol names.
2.  The crafted PDB file is delivered to the target system, potentially through social engineering or as part of a larger attack chain.
3.  A user, unaware of the malicious nature of the PDB file, attempts to analyze it using radare2.
4.  The user executes the `idp` command within radare2 to parse and load debug symbols from the PDB file.
5.  During the parsing process, the `print_gvars()` function is called within the PDB parser.
6.  The function attempts to rename flags based on the symbol names read from the PDB file.
7.  Due to the lack of proper sanitization, the newline characters in the symbol names are interpreted as command separators.
8.  The injected radare2 commands are executed by the shell execution operator, leading to arbitrary OS command execution. The attacker achieves arbitrary command execution on the system.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary commands on the system where radare2 is running. The impact ranges from system compromise and data theft to denial of service, depending on the privileges of the user running radare2 and the commands injected by the attacker. The CVSS v3.1 base score is rated as 7.8 (High).

## Recommendation

*   Upgrade radare2 to version 6.1.4 or later to patch CVE-2026-40517.
*   Implement strict input validation and sanitization for PDB files processed by radare2 to prevent command injection.
*   Deploy the Sigma rule `Detect Suspicious Radare2 Process Execution` to identify potential exploitation attempts.
*   Monitor radare2 process execution for unusual command line arguments (see `Detect Suspicious Radare2 Process Execution`).
