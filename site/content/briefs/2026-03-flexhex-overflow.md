---
title: FlexHEX 2.71 Local Buffer Overflow Vulnerability (CVE-2019-25627)
slug: 2026-03-flexhex-overflow
description: FlexHEX 2.71 is vulnerable to a local buffer overflow in the Stream Name field, allowing local attackers to execute arbitrary code via a structured exception handler (SEH) overflow.
date: "2026-03-24T12:16:02Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - buffer-overflow
  - seh-overflow
  - local-privilege-escalation
  - windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25627
  - https://www.exploit-db.com/exploits/46665
  - https://www.vulncheck.com/advisories/flexhex-local-buffer-overflow-via-seh-unicode
rules:
  - title: Detect Calc.exe spawned by FlexHEX
    description: Detects the execution of calc.exe as a child process of FlexHEX, which may indicate successful exploitation of CVE-2019-25627.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect FlexHEX Writing Executables to Temp Directory
    description: Detects FlexHEX writing executable files to the temp directory, which could indicate shellcode being written for execution.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - file_event
      - windows
rules_count: 2
---

FlexHEX 2.71 is susceptible to a local buffer overflow vulnerability (CVE-2019-25627) found within the Stream Name field. This flaw enables a local attacker to execute arbitrary code by exploiting a structured exception handler (SEH) overflow. The attack involves crafting a malicious text file containing precisely aligned shellcode and SEH chain pointers. By pasting this crafted content into the Stream Name dialog within FlexHEX, the attacker can trigger the SEH overflow and execute commands…
