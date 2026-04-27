---
title: Microsoft Graphics Component Heap-based Buffer Overflow Vulnerability (CVE-2026-32221)
slug: 2026-04-ms-graphics-overflow
description: CVE-2026-32221 is a heap-based buffer overflow vulnerability in the Microsoft Graphics Component, allowing a local attacker to execute arbitrary code.
date: "2026-04-14T18:17:30Z"
severities:
  - high
tags:
  - cve-2026-32221
  - buffer-overflow
  - local-privilege-escalation
  - graphics-component
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32221
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32221
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32221
ioc_counts:
  email: 1
rules:
  - title: Suspicious Process Creation After Graphics Component Error
    description: Detects process creation events immediately following a graphics component error or crash, which may indicate exploitation of CVE-2026-32221.
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
  - title: Detect Potential Exploitation of Graphics Component via Command Line
    description: Detects command-line execution patterns indicative of potential exploitation attempts targeting the Microsoft Graphics Component.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-32221 describes a heap-based buffer overflow vulnerability residing within the Microsoft Graphics Component. This flaw allows an attacker with local access to execute arbitrary code on a vulnerable system. The vulnerability stems from improper handling of memory allocation within the graphics component when processing malformed or specially crafted image files or graphics data. An unauthenticated, local attacker could exploit this vulnerability to gain elevated privileges or…
