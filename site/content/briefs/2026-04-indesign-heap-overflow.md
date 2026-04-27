---
title: Adobe InDesign Heap-Based Buffer Overflow Vulnerability (CVE-2026-34629)
slug: 2026-04-indesign-heap-overflow
description: Adobe InDesign versions 20.5.2, 21.2 and earlier are vulnerable to a heap-based buffer overflow (CVE-2026-34629) that could lead to arbitrary code execution if a user opens a malicious file.
date: "2026-04-15T12:00:00Z"
severities:
  - high
tags:
  - cve-2026-34629
  - heap-overflow
  - adobe-indesign
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-34629
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34629
  - https://helpx.adobe.com/security/products/indesign/apsb26-32.html
rules:
  - title: Detect InDesign Spawning Suspicious Processes
    description: Detects InDesign spawning command interpreters or other suspicious processes, potentially indicating exploitation of CVE-2026-34629
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1053.005
      - T1059.001
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect InDesign Writing Executables
    description: Detects InDesign writing executable files to disk, which could indicate exploitation leading to malware installation.
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

Adobe InDesign Desktop versions 20.5.2, 21.2, and earlier are susceptible to a heap-based buffer overflow vulnerability identified as CVE-2026-34629. This vulnerability allows for arbitrary code execution within the security context of the currently logged-in user. To exploit this vulnerability, a user must interact with a specially crafted malicious file. Successful exploitation could allow an attacker to gain control of the affected system, potentially leading to data theft, malware…
