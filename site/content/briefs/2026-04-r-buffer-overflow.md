---
title: R i386 3.5.0 Local Buffer Overflow Vulnerability (CVE-2019-25656)
slug: 2026-04-r-buffer-overflow
description: R i386 version 3.5.0 is susceptible to a local buffer overflow in the GUI Preferences dialog, allowing a local attacker to overwrite the structured exception handler (SEH) by supplying a malicious string to the 'Language for menus and messages' field, leading to arbitrary code execution.
date: "2026-04-05T21:16:42Z"
severities:
  - high
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
ioc_counts:
  email: 1
  url: 4
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

R i386 version 3.5.0 contains a local buffer overflow vulnerability, identified as CVE-2019-25656, within the GUI Preferences dialog. This vulnerability allows a local attacker to achieve arbitrary code execution by exploiting a buffer overflow when the application processes user-supplied input in the 'Language for menus and messages' field. By crafting a malicious payload string, an attacker can overwrite the Structured Exception Handler (SEH) records. Successful exploitation would allow…
