---
title: Multi Emulator Super System (MESS) Buffer Overflow Vulnerability (CVE-2016-20039)
slug: 2026-03-mess-buffer-overflow
description: Multi Emulator Super System 0.154-3.1 is vulnerable to a buffer overflow (CVE-2016-20039) allowing local attackers to achieve arbitrary code execution by supplying a malicious gamma parameter, leading to potential system compromise.
date: "2026-03-28T12:15:59Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve
  - buffer overflow
  - code execution
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2016-20039
  - http://mamedev.org/
  - https://www.exploit-db.com/exploits/39673
  - https://www.vulncheck.com/advisories/multi-emulator-super-system-buffer-overflow
rules:
  - title: Detect Suspicious MESS Process Invocation
    description: Detects the invocation of the Multi Emulator Super System (MESS) process with potentially malicious command-line arguments related to gamma settings.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect Stack Overflow via Gamma Parameter
    description: Detects a potential stack overflow attempt in Multi Emulator Super System by monitoring process crashes associated with manipulated gamma parameters.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - application
      - windows
rules_count: 2
---

Multi Emulator Super System (MESS) version 0.154-3.1 is susceptible to a buffer overflow vulnerability, identified as CVE-2016-20039. This flaw resides in the handling of the "gamma" parameter. A local attacker can exploit this vulnerability by providing an overly large value for the gamma parameter. Successful exploitation allows the attacker to overwrite the stack buffer, potentially leading to arbitrary code execution and complete system compromise. This vulnerability was reported in March…
