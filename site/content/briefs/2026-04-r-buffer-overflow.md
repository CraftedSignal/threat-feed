---
title: R i386 3.5.0 Local Buffer Overflow Vulnerability (CVE-2019-25656)
slug: 2026-04-r-buffer-overflow
description: R i386 version 3.5.0 is susceptible to a local buffer overflow in the GUI Preferences dialog, allowing a local attacker to overwrite the structured exception handler (SEH) by supplying a malicious string to the 'Language for menus and messages' field, leading to arbitrary code execution.
date: "2026-04-05T21:16:42Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - buffer-overflow
  - seh-overwrite
  - code-execution
  - cve-2019-25656
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2019-25656
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25656
  - https://cran.r-project.org/bin/windows/base/old/3.5.0/R-3.5.0-win.exe
  - https://www.exploit-db.com/exploits/46288
  - https://www.r-project.org/
  - https://www.vulncheck.com/advisories/r-i386-local-buffer-overflow-seh
iocs:
  - type: url
    value: https://cran.r-project.org/bin/windows/base/old/3.5.0/R-3.5.0-win.exe
ioc_counts:
  url: 1
rules:
  - title: Detect R application executing with long command line arguments
    description: Detects R application executing with unusually long command line arguments, potentially indicating a buffer overflow attempt.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Unusual Child Processes of R Application
    description: Detects creation of unusual child processes from the R application, potentially indicating code execution after a buffer overflow.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1106
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

R i386 version 3.5.0 contains a local buffer overflow vulnerability, identified as CVE-2019-25656, within the GUI Preferences dialog. This vulnerability allows a local attacker to achieve arbitrary code execution by exploiting a buffer overflow when the application processes user-supplied input in the 'Language for menus and messages' field. By crafting a malicious payload string, an attacker can overwrite the Structured Exception Handler (SEH) records. Successful exploitation would allow attackers to execute arbitrary code with the privileges of the user running the application. This poses a significant risk to systems running this vulnerable version of R, potentially leading to complete system compromise.

## Attack Chain

1.  Attacker gains local access to a Windows system running R i386 3.5.0.
2.  Attacker opens the R application.
3.  Attacker navigates to the GUI Preferences dialog within the R application.
4.  Attacker identifies the 'Language for menus and messages' field within the GUI Preferences.
5.  Attacker crafts a malicious payload string designed to overwrite SEH records, including shellcode for arbitrary code execution.
6.  Attacker inputs the malicious string into the 'Language for menus and messages' field.
7.  The R application attempts to process the attacker-supplied string without proper bounds checking, triggering the buffer overflow.
8.  The crafted payload overwrites the SEH record, redirecting execution flow to the attacker-controlled shellcode, resulting in arbitrary code execution.

## Impact

Successful exploitation of this vulnerability allows a local attacker to execute arbitrary code on the targeted system. The impact includes potential privilege escalation, allowing the attacker to perform actions with the same privileges as the user running the R application. This could lead to the installation of malware, data exfiltration, or complete system compromise. While specific victim numbers are not available, any system running the vulnerable R i386 3.5.0 is at risk.

## Recommendation

*   Upgrade R to a version higher than 3.5.0 to patch CVE-2019-25656.
*   Deploy the Sigma rule to detect the execution of R with a modified command line containing long strings to identify potential exploit attempts.
*   Monitor network connections originating from R processes for suspicious outbound traffic using network connection logs.
*   Implement the Sigma rule to detect abnormal process execution originating from the R application to catch potential exploitation attempts.
