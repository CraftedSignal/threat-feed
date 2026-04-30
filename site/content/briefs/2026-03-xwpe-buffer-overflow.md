---
title: xwpe Stack-Based Buffer Overflow Vulnerability (CVE-2016-20037)
slug: 2026-03-xwpe-buffer-overflow
description: A stack-based buffer overflow vulnerability exists in xwpe version 1.5.30a-2.1 and prior, allowing a local attacker to execute arbitrary code or cause denial of service by supplying a crafted command-line argument with an overly long input string.
date: "2026-03-28T12:15:58Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve
  - buffer-overflow
  - code-execution
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2016-20037
  - http://www.identicalsoftware.com/xwpe
  - https://www.exploit-db.com/exploits/39285
  - https://www.vulncheck.com/advisories/xwpe-30a-stack-based-buffer-overflow
rules:
  - title: Detect Suspicious xwpe Command Line Arguments
    description: Detects suspicious xwpe command line arguments with lengths exceeding a threshold, potentially indicating a buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1210
    data_sources:
      - process_creation
      - windows
  - title: Detect Shellcode in xwpe Command Line Arguments
    description: Detects potentially malicious shellcode within xwpe command line arguments, indicating a buffer overflow exploit attempt.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1210
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The xwpe application, version 1.5.30a-2.1 and prior, contains a stack-based buffer overflow vulnerability (CVE-2016-20037). This vulnerability allows a local attacker to execute arbitrary code or cause a denial of service. The attack involves crafting a malicious command-line argument with an input string exceeding buffer boundaries. Specifically, the attacker can supply 262 bytes of junk data, followed by shellcode, to overwrite the instruction pointer and gain control of the application's…
