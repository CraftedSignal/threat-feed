---
title: Allok Video to DVD Burner Stack-Based Buffer Overflow Vulnerability (CVE-2018-25303)
slug: 2026-04-allok-video-buffer-overflow
description: Allok Video to DVD Burner 2.6.1217 contains a stack-based buffer overflow vulnerability (CVE-2018-25303) in the License Name field, allowing a local attacker to execute arbitrary code by triggering a structured exception handler (SEH) overwrite.
date: "2026-04-29T20:16:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - buffer overflow
  - seh overwrite
vendors:
  - AllokSoft
products:
  - Allok Video to DVD Burner 2.6.1217
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
cves:
  - id: CVE-2018-25303
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25303
  - https://www.exploit-db.com/exploits/44518
  - https://www.vulncheck.com/advisories/allok-video-to-dvd-burner-buffer-overflow-seh
rules:
  - title: Allok Video to DVD Burner Suspicious Child Process
    description: Detects suspicious child processes spawned by Allok Video to DVD Burner which could indicate successful exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1210
    data_sources:
      - process_creation
      - windows
  - title: Allok Video to DVD Burner Registry Modification
    description: Detects registry modifications made by Allok Video to DVD Burner which could indicate persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1210
      - T1547.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

A stack-based buffer overflow vulnerability exists in Allok Video to DVD Burner version 2.6.1217. This vulnerability, identified as CVE-2018-25303, resides within the "License Name" field of the application. A local attacker can exploit this flaw by crafting a malicious input designed to overwrite the Structured Exception Handler (SEH). Successful exploitation enables the attacker to execute arbitrary code within the context of the application. The vulnerability was reported on 2026-04-29. This is important for defenders because successful exploitation can lead to complete system compromise on vulnerable machines.

## Attack Chain

1.  The attacker gains local access to a system with Allok Video to DVD Burner 2.6.1217 installed.
2.  The attacker crafts a malicious input string consisting of 780 bytes of arbitrary data.
3.  The attacker appends SEH chain pointers and shellcode to the crafted input string.
4.  The attacker opens the Allok Video to DVD Burner application and navigates to the registration window.
5.  The attacker pastes the malicious input string into the "License Name" field.
6.  The application attempts to process the oversized input, triggering the buffer overflow.
7.  The SEH is overwritten with the attacker's controlled pointers.
8.  The shellcode is executed, giving the attacker arbitrary code execution on the system.

## Impact

Successful exploitation of this vulnerability allows a local attacker to execute arbitrary code within the context of the Allok Video to DVD Burner application. This could lead to complete system compromise, including data theft, installation of malware, or other malicious activities. The vulnerability affects version 2.6.1217 of the software. The number of potential victims depends on the number of installations of the vulnerable software.

## Recommendation

*   Monitor process creations for Allok Video to DVD Burner and unusual child processes using the process creation rule below.
*   Monitor for registry modifications performed by the vulnerable application that may indicate persistence.
*   Due to the age of the application, consider whether it should continue to be used within the environment.
