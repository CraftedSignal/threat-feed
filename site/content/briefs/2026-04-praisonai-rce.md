---
title: PraisonAI Subprocess Sandbox Escape Vulnerability (CVE-2026-34955)
slug: 2026-04-praisonai-rce
description: PraisonAI versions prior to 4.5.97 are vulnerable to OS Command Injection (CVE-2026-34955) due to insufficient input validation in the SubprocessSandbox, allowing for trivial sandbox escapes.
date: "2026-04-04T00:16:19Z"
severities:
  - critical
tags:
  - cve
  - rce
  - sandbox-escape
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569
    technique_name: System Services
cves:
  - id: CVE-2026-34955
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34955
  - https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-r4f2-3m54-pp7q
rules:
  - title: Detect PraisonAI Sandbox Escape via sh or bash
    description: Detects attempts to escape the PraisonAI SubprocessSandbox by executing commands through `sh` or `bash`.
    platform: sigma
    severity: critical
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1569.002
    data_sources:
      - process_creation
      - linux
  - title: Detect PraisonAI Process Spawning Shell
    description: Detects PraisonAI processes spawning a shell, which may indicate a sandbox escape attempt.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1569.002
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

PraisonAI, a multi-agent teams system, contains a critical vulnerability (CVE-2026-34955) in versions prior to 4.5.97. The vulnerability lies within the SubprocessSandbox, which is responsible for executing subprocesses in a controlled environment. The SubprocessSandbox, regardless of its configured mode (BASIC, STRICT, NETWORK_ISOLATED), uses `subprocess.run()` with `shell=True`. This approach, coupled with a reliance on simple string-pattern matching for command blocking, creates an…
