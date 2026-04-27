---
title: Qualcomm Memory Corruption Vulnerability (CVE-2026-21371)
slug: 2026-04-qualcomm-memory-corruption
description: CVE-2026-21371 is a memory corruption vulnerability due to insufficient size validation when retrieving an output buffer, potentially leading to information disclosure or arbitrary code execution on affected Qualcomm devices.
date: "2026-04-06T16:16:29Z"
severities:
  - high
tags:
  - cve
  - memory-corruption
  - qualcomm
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-21371
    cvss: 7.8
references:
  - https://docs.qualcomm.com/product/publicresources/securitybulletin/april-2026-bulletin.html
  - https://nvd.nist.gov/vuln/detail/CVE-2026-21371
rules:
  - title: Detect Potential Buffer Over-Read Exploitation
    description: Detects process creation events potentially related to buffer over-read exploitation attempts by monitoring for anomalous memory access patterns.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Memory Access Violation
    description: Detects potential memory access violations indicating exploitation of memory corruption vulnerabilities.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-21371 is a memory corruption vulnerability present in certain Qualcomm products. The vulnerability stems from insufficient size validation when retrieving an output buffer. This flaw can lead to a buffer over-read (CWE-126), potentially allowing a malicious actor with local access to read sensitive information from memory or execute arbitrary code. The vulnerability was reported by Qualcomm and affects undisclosed products. Publicly available information is limited, making it difficult…
