---
title: tufantunc ssh-mcp Command Injection Vulnerability (CVE-2026-7039)
slug: 2026-04-ssh-mcp-command-injection
description: A command injection vulnerability exists in tufantunc ssh-mcp up to version 1.5.0 via manipulation of the Description argument in the shell.write function.
date: "2026-04-27T12:00:00Z"
severities:
  - high
tags:
  - command-injection
  - vulnerability
  - ssh-mcp
vendors:
  - tufantunc
products:
  - ssh-mcp
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-7039
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7039
  - https://github.com/tufantunc/ssh-mcp/
  - https://github.com/tufantunc/ssh-mcp/issues/44
  - https://vuldb.com/submit/798528
  - https://vuldb.com/vuln/359619
  - https://vuldb.com/vuln/359619/cti
rules:
  - title: Detect Command Injection via ssh-mcp
    description: Detects potential command injection attempts originating from ssh-mcp by monitoring for suspicious process creation events.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Command Injection via ssh-mcp (Windows)
    description: Detects potential command injection attempts originating from ssh-mcp on Windows by monitoring for suspicious process creation events.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A command injection vulnerability, tracked as CVE-2026-7039, affects tufantunc ssh-mcp versions up to 1.5.0. The vulnerability resides in the `shell.write` function within the `src/index.ts` file. By manipulating the `Description` argument, a local attacker can inject arbitrary commands. Publicly disclosed exploits exist, increasing the risk of exploitation. The project maintainers have been notified but have not yet responded. This vulnerability poses a significant risk to systems where…
