---
title: UniFi Play Command Injection Vulnerability (CVE-2026-22563)
slug: 2026-04-unifi-command-injection
description: A malicious actor with access to the UniFi Play network can exploit improper input validation vulnerabilities (CVE-2026-22563) in UniFi Play PowerAmp and Audio Port to inject commands, potentially leading to arbitrary code execution.
date: "2026-04-13T22:16:28Z"
severities:
  - critical
tags:
  - command-injection
  - unifi
  - cve-2026-22563
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-22563
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22563
  - https://community.ui.com/releases/Security-Advisory-Bulletin-063/e468dd4b-5090-4ef8-89d8-939903c08e83
ioc_counts:
  url: 1
rules:
  - title: Detect Command Injection Attempt via URI
    description: Detects potential command injection attempts in HTTP requests based on suspicious URI patterns.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Command Injection via POST Request Body
    description: Detects potential command injection attempts in HTTP POST request bodies based on suspicious patterns.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-22563 describes a critical command injection vulnerability affecting UniFi Play PowerAmp (version 1.0.35 and earlier) and UniFi Play Audio Port (version 1.0.24 and earlier). The vulnerability stems from improper input validation, which allows an attacker with access to the UniFi Play network to inject arbitrary commands. Successful exploitation could lead to unauthorized access, system compromise, and potentially full control of the affected devices. This vulnerability was reported to…
