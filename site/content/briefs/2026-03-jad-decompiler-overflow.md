---
title: JAD Java Decompiler Stack-Based Buffer Overflow Vulnerability
slug: 2026-03-jad-decompiler-overflow
description: JAD Java Decompiler 1.5.8e-1kali1 and prior is vulnerable to a stack-based buffer overflow, allowing attackers to execute arbitrary code by providing overly long input to the jad command leading to a return-oriented programming chain execution and shell spawning.
date: "2026-03-28T12:16:01Z"
severities:
  - critical
tags:
  - cve
  - buffer_overflow
  - java_decompiler
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2017-20227
  - http://www.varaneckas.com/jad/
  - https://www.exploit-db.com/exploits/42255
  - https://www.vulncheck.com/advisories/jad-8e-1kali1-stack-based-buffer-overflow
rules:
  - title: Detect JAD Decompiler with Excessive CommandLine Length
    description: Detects execution of JAD Java Decompiler with an excessively long command line, potentially indicating a buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious Shell Spawned by JAD
    description: Detects the spawning of a shell process as a child of the JAD process, which could indicate successful exploitation of CVE-2017-20227
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

JAD Java Decompiler version 1.5.8e-1kali1 and prior contains a critical stack-based buffer overflow vulnerability (CVE-2017-20227). An attacker can exploit this flaw by crafting a malicious input that, when processed by the `jad` command, overflows the stack buffer. This overflow can be leveraged to overwrite critical memory regions, allowing the attacker to inject and execute arbitrary code. The successful exploitation results in the execution of a return-oriented programming (ROP) chain…
