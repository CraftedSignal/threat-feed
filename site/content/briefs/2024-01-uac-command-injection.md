---
title: UAC (Unix-like Artifacts Collector) Command Injection Vulnerability
slug: 2024-01-uac-command-injection
description: UAC before 3.3.0-rc1 is vulnerable to command injection in the _run_command() function, allowing attackers to execute arbitrary commands with the privileges of the UAC process through manipulated input values.
date: "2026-04-08T22:16:23Z"
severities:
  - high
tags:
  - command-injection
  - vulnerability
  - uac
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-40032
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40032
rules:
  - title: Detect Suspicious Processes Spawned by UAC
    description: Detects suspicious processes spawned by UAC, indicating potential command injection exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect UAC Executing Eval
    description: Detects the execution of `eval` commands from the UAC (Unix-like Artifacts Collector) process, which is indicative of potential command injection exploitation.
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

UAC (Unix-like Artifacts Collector) before version 3.3.0-rc1 is susceptible to a command injection vulnerability. This flaw resides in the placeholder substitution and command execution pipeline within the application. Specifically, the `_run_command()` function directly passes constructed command strings to `eval` without proper sanitization. This lack of input validation allows attackers to inject malicious shell metacharacters or command substitutions into the command strings. Exploitation…
