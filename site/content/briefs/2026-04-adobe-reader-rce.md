---
title: Adobe Acrobat and Reader CVE-2026-34621 Zero-Day Exploitation
slug: 2026-04-adobe-reader-rce
description: Adobe patched CVE-2026-34621, a zero-day vulnerability in Acrobat and Reader exploited since December, allowing malicious PDFs to bypass sandboxes and execute arbitrary code, potentially leading to local file theft.
date: "2026-04-13T15:37:41Z"
severities:
  - critical
exploited: true
tags:
  - adobe
  - acrobat
  - reader
  - rce
  - vulnerability
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
cves:
  - id: CVE-2026-34621
    cvss: 8.6
    epss: 0.07596
references:
  - https://www.bleepingcomputer.com/news/security/adobe-rolls-out-emergency-fix-for-acrobat-reader-zero-day-flaw/
ioc_counts:
  filename: 1
rules:
  - title: Detect Execution of Suspicious JavaScript in PDFs
    description: Detects the execution of JavaScript within PDF files that may be indicative of exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - process_creation
      - windows
  - title: Detect PDF Opening with Suspicious Filename
    description: Detects the opening of a PDF file with a suspicious name, such as those used in exploit attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Adobe has addressed CVE-2026-34621, a zero-day vulnerability affecting Acrobat DC, Acrobat Reader DC, and Acrobat 2024 versions on both Windows and macOS. This flaw has been actively exploited in the wild since at least December, with initial discovery occurring after a malicious PDF sample named "yummy_adobe_exploit_uwu.pdf" was submitted for analysis. The vulnerability allows specially crafted PDF files to bypass sandbox restrictions, invoke privileged JavaScript APIs, and potentially execute…
