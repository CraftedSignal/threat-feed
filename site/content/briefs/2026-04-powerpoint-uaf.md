---
title: Microsoft PowerPoint Use-After-Free Vulnerability (CVE-2026-32200)
slug: 2026-04-powerpoint-uaf
description: CVE-2026-32200 is a use-after-free vulnerability in Microsoft Office PowerPoint that allows an unauthorized attacker to achieve local code execution by enticing a user to open a specially crafted PowerPoint document.
date: "2026-04-14T18:17:26Z"
severities:
  - high
tags:
  - cve-2026-32200
  - use-after-free
  - powerpoint
  - code-execution
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2026-32200
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32200
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32200
ioc_counts:
  email: 2
rules:
  - title: Detect Suspicious PowerPoint Child Processes
    description: Detects suspicious child processes spawned by PowerPoint, indicating potential exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect PowerPoint launching MSHTA
    description: Detects potential exploitation via PowerPoint launching MSHTA.exe, which is often used to execute HTA files.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1218.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-32200 is a use-after-free vulnerability affecting Microsoft Office PowerPoint. An unauthenticated, local attacker can exploit this flaw to achieve arbitrary code execution. The attacker needs to convince a user to open a malicious PowerPoint file. Successful exploitation allows the attacker to execute code with the privileges of the current user. Given the widespread use of PowerPoint in corporate environments and the potential for phishing attacks delivering malicious documents, this…
