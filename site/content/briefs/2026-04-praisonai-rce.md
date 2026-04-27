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

PraisonAI, a multi-agent teams system, is susceptible to an OS command injection vulnerability (CVE-2026-34935) affecting versions 4.5.15 to before 4.5.69. The vulnerability stems from the `--mcp` CLI argument being passed directly to `shlex.split()` and subsequently to `anyio.open_process()` without any form of validation, allowlisting, or sanitization. This lack of input sanitization enables an attacker to inject and execute arbitrary operating system commands as the user running the…
