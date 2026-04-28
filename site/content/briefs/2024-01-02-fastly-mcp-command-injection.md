---
title: FastlyMCP Command Injection Vulnerability (CVE-2026-7220)
slug: 2024-01-02-fastly-mcp-command-injection
description: A command injection vulnerability (CVE-2026-7220) exists in jackwrichards FastlyMCP allowing remote attackers to execute arbitrary OS commands by manipulating the command argument in the fastly-mcp.mjs file.
date: "2024-01-02T12:00:00Z"
severities:
  - high
tags:
  - command-injection
  - cve-2026-7220
  - fastly-mcp
products:
  - FastlyMCP
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-7220
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7220
rules:
  - title: Detect FastlyMCP Command Injection Attempt
    description: Detects attempts to exploit the FastlyMCP command injection vulnerability by monitoring for suspicious parameters in web server logs.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Process Execution via FastlyMCP
    description: Detects suspicious processes spawned by the FastlyMCP application, indicating potential command injection exploitation.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A command injection vulnerability, identified as CVE-2026-7220, has been discovered in jackwrichards FastlyMCP up to commit 6f3d0b0e654fc51076badc7fa16c03c461f95620. The vulnerability resides within the `fastly-mcp.mjs` file of the `fastly_cli Tool` component. Successful exploitation allows a remote attacker to inject and execute arbitrary operating system commands by manipulating the `command` argument. The exploit is publicly known and actively usable. Given FastlyMCP's rolling release model…
