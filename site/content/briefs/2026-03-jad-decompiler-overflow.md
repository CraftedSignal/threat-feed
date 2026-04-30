---
title: JAD Java Decompiler Stack-Based Buffer Overflow Vulnerability
slug: 2026-03-jad-decompiler-overflow
description: JAD Java Decompiler 1.5.8e-1kali1 and prior is vulnerable to a stack-based buffer overflow, allowing attackers to execute arbitrary code by providing overly long input to the jad command leading to a return-oriented programming chain execution and shell spawning.
date: "2026-03-28T12:16:01Z"
type: advisory
types:
  - advisory
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

JAD Java Decompiler version 1.5.8e-1kali1 and prior contains a critical stack-based buffer overflow vulnerability (CVE-2017-20227). An attacker can exploit this flaw by crafting a malicious input that, when processed by the `jad` command, overflows the stack buffer. This overflow can be leveraged to overwrite critical memory regions, allowing the attacker to inject and execute arbitrary code. The successful exploitation results in the execution of a return-oriented programming (ROP) chain, ultimately leading to the spawning of a shell with the privileges of the user running the vulnerable JAD decompiler. This vulnerability poses a significant risk to developers and systems utilizing the affected versions of JAD, particularly in environments where untrusted or externally sourced Java bytecode is routinely decompiled.

## Attack Chain

1. An attacker crafts a malicious Java class file or other input designed to trigger the buffer overflow in JAD.
2. The attacker lures a user or system into using the vulnerable JAD decompiler version 1.5.8e-1kali1 or prior to decompile the malicious input file using the `jad` command.
3. JAD attempts to process the overly long input string, exceeding the boundaries of a stack-based buffer.
4. The buffer overflow corrupts the stack, overwriting return addresses and other critical data.
5. The attacker-controlled return addresses are used to construct a return-oriented programming (ROP) chain.
6. The ROP chain executes a series of small code snippets already present in the JAD binary or system libraries to achieve a desired outcome, such as disabling security features or preparing for shell execution.
7. The ROP chain prepares the environment and executes a system call to spawn a shell.
8. The attacker gains arbitrary code execution within the context of the user running JAD.

## Impact

Successful exploitation of CVE-2017-20227 can lead to arbitrary code execution, potentially granting an attacker complete control over the affected system. Given a CVSS v3.1 base score of 9.8 (Critical), this vulnerability poses a severe risk. The impact includes full compromise of confidentiality, integrity, and availability. The attack requires no privileges and no user interaction. This can enable lateral movement within a network, data exfiltration, installation of malware, or other malicious activities.

## Recommendation

*   Implement a network-level block or alert for outbound connections originating from the system running the JAD decompiler, especially if the user routinely decompiles untrusted class files. (Log Source: `network_connection`)
*   Monitor process executions for the `jad` command with unusually long command-line arguments, indicative of a potential buffer overflow attempt. Deploy the provided Sigma rule for detection. (Log Source: `process_creation`)
*   Consider using alternative Java decompilers that are not vulnerable to this specific stack-based buffer overflow.
