---
title: Fortinet FortiSandbox OS Command Injection Vulnerability (CVE-2026-39808)
slug: 2026-04-fortinet-os-command-injection
description: Fortinet FortiSandbox versions 4.4.0 through 4.4.8 are vulnerable to OS Command Injection (CVE-2026-39808), potentially allowing unauthenticated attackers to execute arbitrary code or commands.
date: "2026-04-15T12:00:00Z"
severities:
  - critical
tags:
  - cve
  - command-injection
  - fortinet
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-39808
    cvss: 9.8
    epss: 0.11271
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39808
  - https://fortiguard.fortinet.com/psirt/FG-IR-26-100
ioc_counts:
  email: 1
rules:
  - title: Detect Potential OS Command Injection Attempts via Web Logs
    description: Detects potential OS command injection attempts in web server logs by looking for common command injection characters.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.002
    data_sources:
      - webserver
      - linux
  - title: Detect access to common command execution binaries from uncommon webserver locations
    description: Detects access to common command execution binaries from uncommon webserver locations, indicating potential command injection
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Fortinet FortiSandbox versions 4.4.0 through 4.4.8 are susceptible to an OS Command Injection vulnerability identified as CVE-2026-39808. The vulnerability stems from an improper neutralization of special elements used in an OS command, potentially enabling attackers to inject and execute unauthorized code or commands on the affected system. The specifics of the attack vector are not detailed in the initial advisory. Successful exploitation could lead to complete system compromise, data theft…
