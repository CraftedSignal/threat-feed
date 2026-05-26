---
title: 10-Strike Network Inventory Explorer Stack-Based Buffer Overflow (CVE-2018-25344)
slug: 2026-05-network-inventory-explorer-overflow
description: 10-Strike Network Inventory Explorer 8.54 contains a stack-based buffer overflow vulnerability in the registration key input field that allows local attackers to execute arbitrary code via SEH overwrite.
date: "2026-05-26T13:37:57Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - buffer-overflow
  - seh-overwrite
  - privilege-escalation
  - execution
  - cve-2018-25344
  - windows
vendors:
  - 10-strike
products:
  - Network Inventory Explorer
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
cves:
  - id: CVE-2018-25344
    cvss: 8.4
    epss: 0.00013
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25344
rules:
  - title: Detect Network Inventory Explorer SEH Overwrite
    description: Detects CVE-2018-25344 exploitation — identifies potential Structured Exception Handler (SEH) overwrites by monitoring for process creations shortly after a Network Inventory Explorer registration attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Network Inventory Explorer Suspicious Registration
    description: Detects CVE-2018-25344 exploitation — identifies process creations by cmd, powershell, wscript, or cscript immediately after a Network Inventory Explorer process creation event, indicating potential exploitation attempts following a malformed registration.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

10-Strike Network Inventory Explorer version 8.54 is vulnerable to a stack-based buffer overflow. A local attacker can exploit this vulnerability (CVE-2018-25344) by providing a specially crafted registration key to the application. This crafted input overflows a buffer on the stack, allowing the attacker to overwrite the Structured Exception Handler (SEH) chain and gain arbitrary code execution with the privileges of the running application. The attacker must have local access to the system where the application is installed to exploit this vulnerability. Successful exploitation allows for arbitrary code execution.

## Attack Chain

1. The attacker crafts a malicious registration key string.
2. The malicious string contains 4188 bytes of padding to reach the buffer overflow point.
3. After the padding, the string includes carefully chosen SEH chain values (a pointer to the next handler and a pointer to the handler itself).
4. The crafted string also contains shellcode designed to perform malicious actions.
5. The attacker opens 10-Strike Network Inventory Explorer 8.54.
6. The attacker navigates to the registration dialog.
7. The attacker pastes the malicious registration key string into the registration key input field.
8. When the application attempts to process the overly long registration key, a stack buffer overflow occurs, overwriting the SEH chain.
9. When an exception is triggered (likely due to the memory corruption), the overwritten SEH handler is invoked, leading to execution of the attacker-supplied shellcode.
10. The attacker achieves arbitrary code execution with the privileges of the Network Inventory Explorer application.

## Impact

Successful exploitation of this buffer overflow vulnerability allows a local attacker to execute arbitrary code on the affected system. Since the code is executed with the privileges of the 10-Strike Network Inventory Explorer application, the attacker can perform actions such as installing malware, accessing sensitive data, or modifying system settings. The CVSS v3.1 base score for this vulnerability is 8.4, indicating a high level of severity.

## Recommendation

*   Deploy the Sigma rule `Detect Network Inventory Explorer SEH Overwrite` to identify attempts to exploit the buffer overflow by detecting suspicious SEH overwrites in process creation logs.
*   Deploy the Sigma rule `Detect Network Inventory Explorer Suspicious Registration` to detect suspicious process creation related to Network Inventory Explorer after a registration attempt.
*   Consider migrating to a different network inventory solution, or isolating the vulnerable application from sensitive data and critical system processes.
