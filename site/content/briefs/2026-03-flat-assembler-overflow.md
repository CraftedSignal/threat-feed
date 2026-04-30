---
title: Flat Assembler Stack-Based Buffer Overflow Vulnerability (CVE-2017-20228)
slug: 2026-03-flat-assembler-overflow
description: Flat Assembler version 1.71.21 is susceptible to a stack-based buffer overflow vulnerability, allowing local attackers to achieve arbitrary code execution by providing a crafted, oversized input file.
date: "2026-03-28T12:16:02Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2017-20228
  - buffer-overflow
  - local-privilege-escalation
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2017-20228
  - http://www.flatassembler.net
  - https://www.exploit-db.com/exploits/42265
  - https://www.vulncheck.com/advisories/flat-assembler-stack-based-buffer-overflow-rop
rules:
  - title: Detect Suspicious Flat Assembler Execution
    description: Detects execution of Flat Assembler (fasm.exe) with abnormally large input file sizes, which might indicate exploitation of CVE-2017-20228.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious File Creation by Flat Assembler
    description: Detects creation of executable files by Flat Assembler (fasm.exe) which might indicate exploitation of CVE-2017-20228.
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1106
    data_sources:
      - file_event
      - windows
rules_count: 2
---

The Flat Assembler (FASM) version 1.71.21 is vulnerable to a stack-based buffer overflow (CVE-2017-20228). This vulnerability allows a local attacker to execute arbitrary code on a vulnerable system. The attack requires the attacker to supply a specially crafted assembly file as input to FASM. By providing an input file larger than 5895 bytes, the attacker can overwrite the instruction pointer, leading to arbitrary code execution. This is achieved through return-oriented programming (ROP)…
