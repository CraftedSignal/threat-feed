---
title: CuteFTP 5.0 XP Local Buffer Overflow Vulnerability (CVE-2018-25366)
slug: 2026-05-cuteftp-buffer-overflow
description: CuteFTP 5.0 XP is vulnerable to a buffer overflow (CVE-2018-25366), allowing local attackers to execute arbitrary code by injecting a malicious payload into the Site Manager label field.
date: "2026-05-26T14:14:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - buffer-overflow
  - code-execution
  - cve
vendors:
  - GlobalSCAPE
products:
  - CuteFTP 5.0 XP
affected_os:
  - Windows XP
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
cves:
  - id: CVE-2018-25366
    cvss: 8.4
    epss: 0.00013
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25366
  - http://installer.globalscape.com/pub/cuteftp/archive/english/cuteftp50.exe
  - https://www.exploit-db.com/exploits/45259
  - https://www.vulncheck.com/advisories/cuteftp-xp-buffer-overflow-via-site-manager-label-field
rules:
  - title: Detect CuteFTP Shellcode Execution
    description: Detects CVE-2018-25366 exploitation — execution of shellcode from CuteFTP process indicating buffer overflow
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Buffer Overflow Shellcode
    description: Detects potential shellcode execution via a series of instructions that are commonly used as stubs for shellcode in buffer overflow attacks.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2018-25366 describes a buffer overflow vulnerability in CuteFTP 5.0 XP. A local attacker can exploit this flaw by crafting a malicious payload and injecting it into the Site Manager label field. The vulnerability exists because the application fails to properly validate the size of user-supplied input before copying it into a fixed-size buffer. Successful exploitation allows the attacker to execute arbitrary code with the privileges of the user running the application. This vulnerability was reported on May 25, 2026, and poses a significant risk to systems running the affected software. The attacker needs local access to the system to exploit this vulnerability.

## Attack Chain

1.  The attacker gains local access to a Windows XP system with CuteFTP 5.0 XP installed.
2.  The attacker opens CuteFTP 5.0 XP.
3.  The attacker navigates to the Site Manager.
4.  The attacker creates a new site or modifies an existing one.
5.  The attacker injects a payload exceeding 520 bytes into the "Site Manager label" field.
6.  The crafted payload overwrites the return address on the stack.
7.  The attacker saves the malicious site configuration, which creates or updates a shortcut or configuration file.
8.  The attacker launches the saved shortcut or configuration file, triggering the buffer overflow and executing shellcode, leading to arbitrary code execution.

## Impact

Successful exploitation of this buffer overflow vulnerability (CVE-2018-25366) allows a local attacker to execute arbitrary code on the affected system. This could lead to complete system compromise, including data theft, installation of malware, or denial of service. Given the age of the vulnerable software (CuteFTP 5.0 XP), systems still running it are likely to be unpatched and highly susceptible to other attacks as well.

## Recommendation

*   Upgrade to a supported version of CuteFTP or migrate to a different FTP client to eliminate the vulnerability.
*   Monitor process creation events for suspicious processes launched from CuteFTP's installation directory to detect potential exploitation attempts, using the rule `Detect CuteFTP Shellcode Execution`.
*   Implement application control policies to prevent execution of unauthorized code within the context of CuteFTP.
*   Enable and review process creation logs to detect the execution of shellcode from non-standard locations, as covered by `Detect Buffer Overflow Shellcode`.
