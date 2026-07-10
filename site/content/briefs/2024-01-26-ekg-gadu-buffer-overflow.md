---
title: EKG Gadu 1.9 Local Buffer Overflow Vulnerability (CVE-2016-20047)
slug: 2024-01-26-ekg-gadu-buffer-overflow
description: EKG Gadu 1.9~pre+r2855-3+b1 is vulnerable to a local buffer overflow (CVE-2016-20047) in username handling, allowing attackers to execute arbitrary code by providing an oversized username string.
date: "2024-01-26T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - buffer-overflow
  - local-privilege-escalation
  - cve-2016-20047
vendors:
  - EKG Gadu
products:
  - EKG Gadu
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2016-20047
  - http://ekg.chmurka.net/
  - https://www.exploit-db.com/exploits/40392
  - https://www.vulncheck.com/advisories/ekg-gadu-local-buffer-overflow-via-username-parameter
rules:
  - title: Detect EKG Gadu Suspicious Process Creation
    description: Detects suspicious process creation originating from EKG Gadu, potentially indicating exploitation of CVE-2016-20047.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Large Input to EKG Gadu via CLI
    description: Detects unusually large input strings passed to EKG Gadu via the command line, which could be a buffer overflow attempt.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

EKG Gadu 1.9~pre+r2855-3+b1 is susceptible to a local buffer overflow vulnerability, identified as CVE-2016-20047. This flaw resides within the application's username handling mechanism. A local attacker can exploit this vulnerability by providing an overly long username string, exceeding the buffer's capacity. Successful exploitation allows the attacker to overwrite the instruction pointer, leading to the execution of arbitrary code with the privileges of the user running EKG Gadu. The vulnerability exists due to the use of `strlcpy` without proper bounds checking. This vulnerability was published on 2026-03-28.

## Attack Chain

1.  Attacker gains local access to a system with EKG Gadu 1.9~pre+r2855-3+b1 installed.
2.  Attacker identifies the vulnerable username handling function within EKG Gadu.
3.  Attacker crafts a malicious input string exceeding 258 bytes intended for the username field.
4.  The attacker triggers the vulnerability by providing the oversized username through the application's interface or configuration.
5.  EKG Gadu attempts to copy the oversized username into a fixed-size buffer using `strlcpy`.
6.  The `strlcpy` function overflows the buffer, overwriting adjacent memory regions, including the instruction pointer.
7.  The attacker's crafted input includes shellcode designed to execute arbitrary commands.
8.  When EKG Gadu attempts to return from the function, it jumps to the attacker-controlled instruction pointer, executing the shellcode and gaining arbitrary code execution.

## Impact

Successful exploitation of CVE-2016-20047 allows a local attacker to execute arbitrary code with the privileges of the user running EKG Gadu. This can lead to complete system compromise, data theft, or denial of service. The vulnerability requires local access, limiting the scope of potential victims to systems where the attacker already has a foothold.

## Recommendation

*   Identify and remove installations of EKG Gadu 1.9~pre+r2855-3+b1 to eliminate the vulnerable application.
*   Monitor process creation events for EKG Gadu spawning unusual processes, as this could indicate exploitation, using the Sigma rule "Detect EKG Gadu Suspicious Process Creation".
*   Implement host-based intrusion detection systems (HIDS) to detect attempts to exploit buffer overflows, with specific focus on applications using the `strlcpy` function.
