---
title: IBM Verify Identity Access and Security Verify Access Command Injection Vulnerability
slug: 2026-04-ibm-verify-rce
description: Unauthenticated command execution is possible in IBM Verify Identity Access Container and IBM Security Verify Access Container due to improper validation of user-supplied input, allowing arbitrary command execution with lower privileges.
date: "2026-04-01T21:16:58Z"
severities:
  - high
tags:
  - command-injection
  - rce
  - cve-2026-1345
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-1345
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-1345
  - https://www.ibm.com/support/pages/node/7268253
rules:
  - title: Detect Suspicious HTTP Request with OS Command Injection Pattern
    description: Detects HTTP requests containing common OS command injection patterns.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious POST Request with OS Command Injection Pattern
    description: Detects HTTP POST requests containing common OS command injection patterns.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
rules_count: 2
---

IBM Verify Identity Access Container versions 11.0 through 11.0.2 and IBM Security Verify Access Container versions 10.0 through 10.0.9.1, as well as IBM Verify Identity Access 11.0 through 11.0.2 and IBM Security Verify Access 10.0 through 10.0.9.1, are vulnerable to command injection. An unauthenticated attacker can exploit this vulnerability (CVE-2026-1345) to execute arbitrary commands with lower user privileges due to insufficient input validation. This poses a significant risk as it could…
