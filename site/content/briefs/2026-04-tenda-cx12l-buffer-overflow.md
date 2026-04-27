---
title: Tenda CX12L Router Stack-Based Buffer Overflow Vulnerability
slug: 2026-04-tenda-cx12l-buffer-overflow
description: A stack-based buffer overflow vulnerability exists in the Tenda CX12L router (version 16.03.53.12) due to improper handling of the 'page' argument in the 'fromwebExcptypemanFilter' function, potentially allowing attackers with local network access to execute arbitrary code.
date: "2026-04-06T22:16:24Z"
severities:
  - high
tags:
  - tenda
  - router
  - buffer-overflow
  - cve-2026-5684
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
cves:
  - id: CVE-2026-5684
    cvss: 8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5684
  - https://github.com/cve-a/lvdan/issues/2
  - https://vuldb.com/vuln/355511
rules:
  - title: Detect Tenda CX12L Web Request with Long Page Parameter
    description: Detects HTTP requests to the vulnerable Tenda CX12L endpoint with a large 'page' parameter, indicating a potential buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda CX12L Stack Buffer Overflow Attempt
    description: Detects suspicious processes spawned after a potential webserver exploit on Tenda CX12L routers, indicative of code execution following a buffer overflow.
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

A critical stack-based buffer overflow vulnerability has been identified in Tenda CX12L routers running firmware version 16.03.53.12. The vulnerability resides within the `fromwebExcptypemanFilter` function in the `/goform/webExcptypemanFilter` file.  An attacker with local network access can exploit this flaw by manipulating the `page` argument passed to this function, leading to arbitrary code execution on the device. The vulnerability, identified as CVE-2026-5684, has a CVSS v3.1 score of…
