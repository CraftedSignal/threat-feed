---
title: RGui 3.5.0 Local Buffer Overflow Vulnerability
slug: 2026-04-rgui-buffer-overflow
description: RGui 3.5.0 contains a local buffer overflow vulnerability in the GUI preferences dialog that allows attackers to bypass DEP protections through structured exception handling exploitation, leading to arbitrary code execution.
date: "2026-04-12T13:16:31Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - buffer-overflow
  - dep-bypass
  - rgui
  - cve-2018-25258
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2018-25258
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25258
  - https://cran.r-project.org/bin/windows/base/old/3.5.0/R-3.5.0-win.exe
  - https://www.exploit-db.com/exploits/46107
  - https://www.r-project.org/
  - https://www.vulncheck.com/advisories/rgui-local-buffer-overflow-seh-dep-bypass
rules:
  - title: Detect RGui.exe Spawning Suspicious Processes
    description: Detects RGui.exe spawning command interpreters or other suspicious processes that may indicate exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Stack-Based Buffer Overflow via SEH Overwrite
    description: Detects potential stack-based buffer overflows that overwrite SEH records by monitoring for execution redirection to unusual memory regions.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

RGui 3.5.0, a component of the R programming language distribution for Windows, is vulnerable to a local buffer overflow in its GUI preferences dialog. This vulnerability, identified as CVE-2018-25258, allows an attacker with local access to bypass Data Execution Prevention (DEP) and execute arbitrary code. The attack involves crafting malicious input to the "Language for menus and messages" field within the GUI preferences, triggering a stack-based buffer overflow. This overflow overwrites the Structured Exception Handler (SEH) record, enabling the attacker to redirect execution flow and execute a Return-Oriented Programming (ROP) chain. The ROP chain is then used to allocate memory using VirtualAlloc and ultimately execute arbitrary code. This vulnerability impacts systems running the affected version of RGui.

## Attack Chain

1.  The attacker gains local access to a Windows system running RGui 3.5.0.
2.  The attacker opens the GUI preferences dialog within RGui.
3.  The attacker inputs a specially crafted string into the "Language for menus and messages" field. This string is designed to overflow the buffer on the stack.
4.  The buffer overflow overwrites the SEH record, replacing the legitimate handler address with the address of a ROP chain.
5.  An exception occurs due to the overflow, triggering the SEH.
6.  Instead of the legitimate exception handler, the attacker's ROP chain is executed.
7.  The ROP chain calls VirtualAlloc to allocate a region of memory with execute permissions.
8.  The attacker copies malicious code into the newly allocated memory and transfers control to it, achieving arbitrary code execution.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code with the privileges of the user running RGui. This could lead to the installation of malware, data theft, or complete system compromise. While the vulnerability requires local access, it represents a significant risk to systems where untrusted users have access to RGui. The vulnerability affects RGui version 3.5.0.

## Recommendation

*   Upgrade to a later version of RGui that addresses the CVE-2018-25258 vulnerability if available.
*   Monitor process creations for `rgui.exe` spawning unusual child processes or making unexpected network connections, using a process creation log source.
*   Implement application whitelisting to prevent the execution of unauthorized programs.
*   Deploy the Sigma rule for detecting potential ROP chain execution to identify exploitation attempts.
