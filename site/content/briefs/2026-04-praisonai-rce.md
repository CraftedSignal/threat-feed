---
title: PraisonAI Unsanitized CLI Argument Leads to OS Command Injection (CVE-2026-34935)
slug: 2026-04-praisonai-rce
description: PraisonAI versions 4.5.15 to before 4.5.69 are vulnerable to OS Command Injection via the --mcp CLI argument, which is passed unsanitized to shlex.split() and anyio.open_process(), allowing arbitrary OS command execution as the process user; version 4.5.69 addresses this vulnerability.
date: "2026-04-03T23:17:05Z"
severities:
  - critical
tags:
  - cve-2026-34935
  - os command injection
  - rce
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1213
    technique_name: Data from Information Repositories
cves:
  - id: CVE-2026-34935
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34935
  - https://github.com/MervinPraison/PraisonAI/commit/47bff65413beaa3c21bf633c1fae4e684348368c
  - https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-9gm9-c8mq-vq7m
rules:
  - title: Detect PraisonAI OS Command Injection Attempt via --mcp Argument
    description: Detects attempts to exploit the PraisonAI OS command injection vulnerability (CVE-2026-34935) by monitoring for suspicious command-line arguments passed to the PraisonAI process.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1213
    data_sources:
      - process_creation
      - linux
  - title: Detect PraisonAI Child Processes
    description: Detect unusual child processes spawned by PraisonAI, indicative of command injection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1213
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

PraisonAI, a multi-agent teams system, is susceptible to an OS command injection vulnerability (CVE-2026-34935) affecting versions 4.5.15 to before 4.5.69. The vulnerability stems from the `--mcp` CLI argument being passed directly to `shlex.split()` and subsequently to `anyio.open_process()` without any form of validation, allowlisting, or sanitization. This lack of input sanitization enables an attacker to inject and execute arbitrary operating system commands as the user running the PraisonAI process. Successful exploitation allows for complete system compromise. Users are advised to upgrade to version 4.5.69 or later to remediate this vulnerability.

## Attack Chain

1.  An attacker crafts a malicious CLI command that includes the `--mcp` argument with an embedded OS command.
2.  The attacker executes the malicious command against the PraisonAI application.
3.  The PraisonAI application receives the `--mcp` argument and passes it to `shlex.split()`.
4.  `shlex.split()` processes the unsanitized input and splits it into command arguments.
5.  The split arguments are then passed to `anyio.open_process()`.
6.  `anyio.open_process()` executes the attacker-controlled OS command as the user running the PraisonAI process.
7.  The attacker gains arbitrary code execution on the host system.
8.  The attacker can then perform lateral movement, data exfiltration, or other malicious activities.

## Impact

Successful exploitation of CVE-2026-34935 allows an attacker to execute arbitrary commands on the affected system with the privileges of the PraisonAI process user. This can lead to complete system compromise, data breaches, and potential disruption of services. Given the severity and ease of exploitation, this vulnerability poses a significant risk to organizations using vulnerable versions of PraisonAI. The number of potential victims is unknown, but all installations between versions 4.5.15 and 4.5.69 are at risk.

## Recommendation

*   Upgrade PraisonAI to version 4.5.69 or later to patch CVE-2026-34935.
*   Implement input validation and sanitization for all CLI arguments, especially those passed to shell commands, to prevent similar vulnerabilities in the future.
*   Monitor process execution for unusual or unexpected commands originating from the PraisonAI process to detect potential exploitation attempts. Use process creation logs with a Sigma rule.
*   Implement the provided Sigma rule to detect suspicious command line arguments passed to PraisonAI.
