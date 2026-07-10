---
title: iSelect 1.4.0-2+b1 Local Buffer Overflow Vulnerability
slug: 2024-01-iselect-buffer-overflow
description: iSelect 1.4.0-2+b1 contains a local buffer overflow vulnerability, allowing local attackers to execute arbitrary code by supplying an oversized value to the -k/--key parameter and overflowing a 1024-byte stack buffer.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2016-20048
  - buffer-overflow
  - local-privilege-escalation
vendors:
  - OSSP
products:
  - iSelect
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2016-20048
  - http://www.ossp.org/pkg/tool/iselect/
  - https://www.exploit-db.com/exploits/41076
  - https://www.vulncheck.com/advisories/iselect-2-b1-local-buffer-overflow-via-key-parameter
rules:
  - title: Detect iSelect Buffer Overflow Attempt
    description: Detects attempts to exploit the iSelect buffer overflow vulnerability by monitoring for unusually long command line arguments passed to iSelect.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect iSelect Shellcode in Argument
    description: Detects potential shellcode within arguments passed to iSelect, indicating a possible buffer overflow exploitation attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

iSelect 1.4.0-2+b1 is vulnerable to a local buffer overflow. This vulnerability allows a local attacker to execute arbitrary code with the privileges of the user running the application. The vulnerability occurs when the application processes an overly long value provided to the `-k` or `--key` parameter. By crafting a malicious argument, an attacker can overwrite the stack buffer, inject shellcode, and gain control of program execution. Successful exploitation can lead to arbitrary code execution and potentially full system compromise within the user's security context. This vulnerability was reported in 2016, but can still exist in unpatched or older systems where iSelect is deployed.

## Attack Chain

1.  Attacker gains local access to a system with iSelect 1.4.0-2+b1 installed.
2.  Attacker crafts a malicious command-line argument for iSelect, specifically targeting the `-k` or `--key` parameter.
3.  The crafted argument includes a NOP sled, followed by shellcode, and a return address that points back to the NOP sled or shellcode. The total length of the argument exceeds 1024 bytes.
4.  The attacker executes iSelect with the malicious argument. The overly long input is copied into a 1024-byte stack buffer without proper bounds checking.
5.  The buffer overflow overwrites adjacent memory on the stack, including the return address.
6.  iSelect attempts to return from the vulnerable function, but instead jumps to the attacker-controlled address (NOP sled or shellcode).
7.  The shellcode executes with the privileges of the user running iSelect. This could involve creating new processes, modifying files, or establishing a reverse shell.

## Impact

Successful exploitation of this vulnerability results in arbitrary code execution with the privileges of the user running iSelect. This could allow an attacker to escalate privileges, install malware, steal sensitive data, or disrupt system operations. Due to the local nature of the attack, an attacker must first gain access to the target system. The severity is high because it allows complete compromise of the application and potentially the user's account.

## Recommendation

*   Upgrade iSelect to a patched version that addresses the buffer overflow vulnerability, if a patch is available.
*   Monitor process execution for iSelect being launched with unusually long command-line arguments using the Sigma rule `Detect iSelect Buffer Overflow Attempt`.
*   Implement access controls to limit who can execute iSelect on vulnerable systems.
*   Consider deploying application whitelisting to prevent the execution of unauthorized code within the iSelect process.
