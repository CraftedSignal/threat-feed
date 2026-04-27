---
title: Adobe Acrobat Reader Prototype Pollution Vulnerability (CVE-2026-34621)
slug: 2026-04-acrobat-prototype-pollution
description: A prototype pollution vulnerability, identified as CVE-2026-34621, exists in Adobe Acrobat Reader versions 24.001.30356, 26.001.21367 and earlier, potentially leading to arbitrary code execution when a user opens a malicious file.
date: "2026-04-11T07:17:00Z"
severities:
  - critical
tags:
  - cve-2026-34621
  - acrobat reader
  - prototype pollution
  - arbitrary code execution
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2026-34621
    cvss: 9.6
    epss: 0.07596
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34621
  - https://helpx.adobe.com/security/products/acrobat/apsb26-43.html
ioc_counts:
  email: 1
rules:
  - title: Detect Acrobat Reader Suspicious Child Process
    description: Detects suspicious child processes spawned by Adobe Acrobat Reader, potentially indicating exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Acrobat Reader Network Connection to Non-Standard Ports
    description: Detects suspicious network connections initiated by Adobe Acrobat Reader to non-standard ports.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-34621 describes a critical vulnerability affecting Adobe Acrobat Reader versions 24.001.30356, 26.001.21367, and earlier. This vulnerability is classified as an Improperly Controlled Modification of Object Prototype Attributes, also known as 'Prototype Pollution'. The vulnerability's exploitation could lead to arbitrary code execution within the context of the current user. The attack requires user interaction, specifically the opening of a specially crafted malicious file by the…
