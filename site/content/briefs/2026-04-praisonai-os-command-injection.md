---
title: PraisonAI OS Command Injection Vulnerability (CVE-2026-34937)
slug: 2026-04-praisonai-os-command-injection
description: PraisonAI versions prior to 1.5.90 are vulnerable to OS Command Injection (CVE-2026-34937) due to insufficient escaping in the run_python() function, allowing arbitrary OS command execution via shell interpolation.
date: "2026-04-03T23:17:06Z"
severities:
  - high
tags:
  - cve-2026-34937
  - os command injection
  - praisonai
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-34937
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34937
  - https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-w37c-qqfp-c67f
rules:
  - title: Detect PraisonAI OS Command Injection Attempt
    description: Detects potential OS command injection attempts in PraisonAI by monitoring for suspicious process executions originating from the PraisonAI application.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.008
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious Subprocess Execution via PraisonAI
    description: Detects potential OS command injection attempts by monitoring for suspicious subprocess.run calls with shell=True in PraisonAI processes.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.008
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

PraisonAI, a multi-agent teams system, is susceptible to an OS command injection vulnerability affecting versions prior to 1.5.90. The vulnerability, identified as CVE-2026-34937, stems from the `run_python()` function's construction of shell command strings. This function interpolates user-controlled code into a `python3 -c "<code>"` command and executes it using `subprocess.run(..., shell=True)`. The inadequate escaping logic, specifically the failure to escape `$()` and backtick…
