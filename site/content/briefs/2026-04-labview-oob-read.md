---
title: NI LabVIEW Out-of-Bounds Read Vulnerability (CVE-2026-32864)
slug: 2026-04-labview-oob-read
description: A memory corruption vulnerability exists in NI LabVIEW due to an out-of-bounds read in mgcore_SH_25_3!aligned_free(), potentially leading to information disclosure or arbitrary code execution if a user opens a specially crafted VI file.
date: "2026-04-08T12:00:00Z"
severities:
  - high
tags:
  - cve-2026-32864
  - labview
  - memory-corruption
  - out-of-bounds-read
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
cves:
  - id: CVE-2026-32864
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32864
  - https://www.ni.com/en/support/security/available-critical-and-security-updates-for-ni-software/2026/memory-corruption-vulnerabilities-in-ni-labview.html
ioc_counts:
  email: 1
rules:
  - title: LabVIEW Suspicious VI File Open
    description: Detects the opening of LabVIEW VI files from unusual locations, potentially indicating a malicious file.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: LabVIEW Suspicious Child Process
    description: Detects LabVIEW spawning unusual child processes, indicating potential code execution from a malicious VI file.
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

A memory corruption vulnerability, identified as CVE-2026-32864, exists within National Instruments (NI) LabVIEW software. The flaw is triggered by an out-of-bounds read within the `mgcore_SH_25_3!aligned_free()` function. An attacker can exploit this vulnerability by enticing a user to open a specially crafted VI (Virtual Instrument) file. Successful exploitation could lead to information disclosure, potentially exposing sensitive data handled by LabVIEW, or arbitrary code execution, granting…
