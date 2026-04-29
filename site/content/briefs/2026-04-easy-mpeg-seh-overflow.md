---
title: Easy MPEG to DVD Burner 1.7.11 SEH Buffer Overflow
slug: 2026-04-easy-mpeg-seh-overflow
description: Easy MPEG to DVD Burner 1.7.11 contains a structured exception handling (SEH) local buffer overflow vulnerability that allows local attackers to execute arbitrary code by supplying a malicious username string.
date: "2026-04-29T20:16:25Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - buffer overflow
  - seh overflow
  - cve-2018-25301
products:
  - Easy MPEG to DVD Burner 1.7.11
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1211
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2018-25301
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25301
  - https://downloads.tomsguide.com/MPEG-Easy-Burner,0301-10418.html
  - https://www.exploit-db.com/exploits/44565
  - https://www.vulncheck.com/advisories/easy-mpeg-to-dvd-burner-seh-local-buffer-overflow
rules:
  - title: Detect Easy MPEG to DVD Burner Process Creation
    description: Detects the execution of Easy MPEG to DVD Burner, which may indicate exploitation attempts.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - process_creation
      - windows
  - title: Detect Calc.exe Spawned by Easy MPEG to DVD Burner
    description: Detects calc.exe being spawned as a child process of Easy MPEG to DVD Burner, indicating a potential successful exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Easy MPEG to DVD Burner 1.7.11 is vulnerable to a structured exception handling (SEH) local buffer overflow. This vulnerability allows a local attacker to execute arbitrary code on a targeted system. The vulnerability can be triggered by supplying a malicious username string to the application. The attacker exploits this vulnerability by overwriting the SEH handler, redirecting execution flow to attacker-controlled shellcode, which can then execute arbitrary commands. This vulnerability exists due to insufficient bounds checking when handling user-supplied data, specifically the username. Successful exploitation allows for arbitrary code execution within the context of the application.

## Attack Chain

1. The attacker crafts a malicious input string designed to trigger a buffer overflow in Easy MPEG to DVD Burner 1.7.11.
2. The malicious string includes junk data to fill the buffer, SEH chain pointers to control the exception handling process, and shellcode containing the attacker's desired commands.
3. The attacker provides the crafted input as a username during application execution, likely via a configuration file or command-line argument.
4. The application's vulnerable code attempts to copy the attacker-controlled username into a fixed-size buffer without proper bounds checking.
5. The buffer overflows, overwriting the SEH handler with the attacker-controlled SEH chain pointers.
6. An exception is triggered within the application due to the buffer overflow, causing the SEH handler to be invoked.
7. The overwritten SEH handler redirects execution to the attacker's shellcode.
8. The shellcode executes arbitrary commands, such as launching calc.exe, giving the attacker control over the system.

## Impact

Successful exploitation of this vulnerability allows a local attacker to execute arbitrary code with the privileges of the user running Easy MPEG to DVD Burner 1.7.11. This can lead to complete system compromise, data theft, or denial of service. While there is no mention of the number of victims or specific sectors targeted in the provided document, the high CVSS score (8.4) indicates a significant risk. The impact would allow lateral movement and further compromise.

## Recommendation

*   Block execution of Easy MPEG to DVD Burner 1.7.11 if it is not a required application.
*   Monitor process creations for unusual processes originating from Easy MPEG to DVD Burner using the process creation rule below.
*   Monitor for unexpected process execution, such as calc.exe (mentioned in the advisory), following the execution of Easy MPEG to DVD Burner 1.7.11.
