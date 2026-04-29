---
title: Alloksoft Video Joiner Buffer Overflow Vulnerability (CVE-2018-25315)
slug: 2026-04-alloksoft-overflow
description: Alloksoft Video Joiner 4.6.1217 is vulnerable to a local buffer overflow (CVE-2018-25315) allowing attackers to execute arbitrary code via a crafted license name.
date: "2026-04-29T20:16:27Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - buffer-overflow
  - code-execution
  - cve-2018-25315
  - windows
vendors:
  - Alloksoft
products:
  - Video joiner 4.6.1217
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2018-25315
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25315
  - http://www.alloksoft.com
  - http://www.alloksoft.com/joiner.htm
  - https://www.exploit-db.com/exploits/44364
  - https://www.vulncheck.com/advisories/alloksoft-video-joiner-buffer-overflow-via-license-name
rules:
  - title: Alloksoft Video Joiner Suspicious Child Process
    description: Detects suspicious child processes spawned by Alloksoft Video Joiner, indicating potential code execution from a buffer overflow.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Alloksoft Video Joiner Outbound Network Connection
    description: Detects outbound network connections initiated by Alloksoft Video Joiner, which is unusual behavior and may indicate command and control.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Alloksoft Video Joiner version 4.6.1217 is susceptible to a buffer overflow vulnerability (CVE-2018-25315). This vulnerability allows a local attacker to execute arbitrary code on a vulnerable system. The attack involves crafting a malicious string and supplying it to the "License Name" field of the application during registration. Exploitation occurs due to the application's failure to properly validate the length of the input, allowing a buffer overflow to occur. The attacker leverages Structured Exception Handler (SEH) overwrite and injects shellcode to gain code execution in the context of the application. This vulnerability was reported in April 2026.

## Attack Chain

1.  The attacker gains local access to a system with Alloksoft Video Joiner 4.6.1217 installed.
2.  The attacker identifies the "License Name" field within the application's registration process as a potential vulnerability point.
3.  The attacker crafts a malicious string that exceeds the expected buffer size for the "License Name" field.
4.  The malicious string includes an SEH overwrite payload, redirecting execution flow to the attacker's controlled memory.
5.  The crafted string also contains shellcode designed to perform arbitrary code execution.
6.  The attacker inputs the malicious string into the "License Name" field and submits the registration form.
7.  The application attempts to process the oversized string, triggering a buffer overflow.
8.  The SEH overwrite redirects execution to the injected shellcode, granting the attacker arbitrary code execution within the context of the Alloksoft Video Joiner process.

## Impact

Successful exploitation of this buffer overflow vulnerability allows a local attacker to execute arbitrary code with the privileges of the Alloksoft Video Joiner application. This could lead to complete system compromise, data theft, or installation of malware. While the specific number of affected users is unknown, any system running the vulnerable version of the software is at risk.

## Recommendation

*   Monitor process creations for `VideoJoiner.exe` spawning unusual child processes, indicative of code execution stemming from the overflow.
*   Consider deploying network egress rules to block connections originating from `VideoJoiner.exe` to external IPs to prevent command and control.
*   Implement application control policies to prevent the execution of unsigned or untrusted code within the context of `VideoJoiner.exe`.
