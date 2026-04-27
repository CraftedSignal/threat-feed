---
title: NI LabVIEW LVLIB File Parsing Memory Corruption Vulnerability (CVE-2026-32860)
slug: 2026-04-labview-lvlib-vuln
description: A memory corruption vulnerability exists in NI LabVIEW due to an out-of-bounds write when loading a corrupted LVLIB file, potentially leading to information disclosure or arbitrary code execution if a user opens a specially crafted .lvlib file.
date: "2026-04-07T20:16:24Z"
severities:
  - high
tags:
  - cve-2026-32860
  - labview
  - memory corruption
  - out-of-bounds write
  - lvlib
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-32860
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32860
  - https://www.ni.com/en/support/security/available-critical-and-security-updates-for-ni-software/2026/lv-project-library-file-parsing-memory-corruption-vulnerability-in-ni-labview.html
ioc_counts:
  url: 1
rules:
  - title: Detect LabVIEW Opening Uncommon File Extensions
    description: Detects LabVIEW opening file extensions that are not typically associated with normal operation, which might indicate malicious LVLIB processing.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Uncommon Child Processes of LabVIEW
    description: Detects the creation of child processes from LabVIEW that are not commonly observed, which can be an indicator of code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-32860 is a vulnerability affecting NI LabVIEW versions 2026 Q1 (26.1.0) and prior. The vulnerability stems from an out-of-bounds write condition encountered during the loading of a corrupted LVLIB (LabVIEW Library) file. An attacker could exploit this flaw by crafting a malicious .lvlib file and enticing a user to open it within LabVIEW. Successful exploitation could lead to memory corruption, potentially enabling information disclosure or the execution of arbitrary code within the…
