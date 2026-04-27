---
title: AIDA64 Extreme 5.99.4900 Structured Exception Handler Buffer Overflow
slug: 2026-03-aida64-buffer-overflow
description: AIDA64 Extreme 5.99.4900 is vulnerable to a structured exception handler buffer overflow, allowing local attackers to execute arbitrary code by supplying a malicious CSV log file path through the Hardware Monitoring logging preferences.
date: "2026-03-24T12:16:02Z"
severities:
  - high
tags:
  - aida64
  - buffer-overflow
  - vulnerability
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25629
  - https://www.vulncheck.com/advisories/aida64-extreme-seh-buffer-overflow-via-logging
  - https://www.exploit-db.com/exploits/46660
ioc_counts:
  url: 4
rules:
  - title: Detect AIDA64 Suspicious Log File Access
    description: Detects AIDA64 accessing potentially malicious CSV log files, indicating a possible buffer overflow attempt.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - file_event
      - windows
  - title: Detect AIDA64 Command Line Process Creation
    description: Detects AIDA64 spawning command-line processes, which is unexpected behavior and could indicate exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

AIDA64 Extreme version 5.99.4900 is susceptible to a structured exception handler (SEH) buffer overflow vulnerability. This flaw enables a local attacker to execute arbitrary code on a targeted system. The attack vector involves crafting a malicious CSV log file path and configuring AIDA64's Hardware Monitoring logging preferences to utilize it. When the AIDA64 application attempts to process this specially crafted log file, it triggers a buffer overflow in the SEH, enabling the attacker to…
