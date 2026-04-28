---
title: R 3.4.4 Local Buffer Overflow Vulnerability (CVE-2019-25695)
slug: 2026-04-r-buffer-overflow
description: R 3.4.4 is vulnerable to a local buffer overflow, allowing attackers to execute arbitrary code by injecting a malicious payload into the GUI Preferences language field.
date: "2026-04-12T13:16:32Z"
severities:
  - high
tags:
  - cve-2019-25695
  - buffer-overflow
  - r
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2019-25695
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25695
  - https://cloud.r-project.org/bin/windows/
  - https://www.exploit-db.com/exploits/46265
  - https://www.vulncheck.com/advisories/r-local-buffer-overflow-windows-xp-sp3
rules:
  - title: Detect R Buffer Overflow - Suspicious Process Creation
    description: Detects suspicious processes spawned by the R application, potentially indicating successful exploitation of CVE-2019-25695.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect R Buffer Overflow - Language Setting Modification
    description: Detects modifications to R language settings that might indicate an attempt to inject malicious code.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

R version 3.4.4 is susceptible to a local buffer overflow vulnerability (CVE-2019-25695). This flaw allows a local attacker to execute arbitrary code on a vulnerable system. The vulnerability is triggered when a crafted payload is injected into the "Language for menus and messages" field within the GUI Preferences. Successful exploitation requires the attacker to paste a specially crafted string into the affected field. The attacker leverages a 292-byte offset combined with a JMP ESP instruction to gain control of the program execution flow. Successful exploitation allows arbitrary code execution, potentially leading to complete system compromise. The vulnerability has been publicly documented and proof-of-concept exploits are available.

## Attack Chain

1.  Attacker gains local access to a Windows system with R 3.4.4 installed.
2.  Attacker crafts a malicious payload containing a 292-byte offset and a JMP ESP instruction.
3.  The attacker opens the R application and navigates to the GUI Preferences.
4.  The attacker locates the "Language for menus and messages" field in the GUI Preferences.
5.  The attacker pastes the malicious payload into the "Language for menus and messages" field.
6.  The R application processes the injected payload, triggering the buffer overflow.
7.  The JMP ESP instruction redirects execution to the attacker-controlled buffer.
8.  The attacker's code is executed, allowing arbitrary commands to run, such as launching calc.exe.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code on the affected system. Given the local nature of the vulnerability, an attacker would need prior access to the system. The impact could range from installing malware and stealing sensitive information to gaining complete control of the compromised machine. While the specific number of affected systems is unknown, any Windows system running R 3.4.4 is potentially vulnerable.

## Recommendation

*   Upgrade R to a version beyond 3.4.4 to patch CVE-2019-25695.
*   Monitor process creation events (logsource `process_creation`, product `windows`) for unusual processes spawned by the R application. Use the provided Sigma rules to detect potential exploitation attempts.
*   Consider implementing application whitelisting to restrict the execution of unauthorized programs, mitigating the impact of successful code execution.
