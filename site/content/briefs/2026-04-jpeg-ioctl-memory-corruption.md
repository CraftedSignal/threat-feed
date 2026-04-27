---
title: 'CVE-2025-47390: JPEG Driver IOCTL Memory Corruption Vulnerability'
slug: 2026-04-jpeg-ioctl-memory-corruption
description: A memory corruption vulnerability (CVE-2025-47390) exists while preprocessing IOCTL requests in the JPEG driver, potentially leading to local privilege escalation or denial of service.
date: "2026-04-06T16:16:27Z"
severities:
  - high
tags:
  - memory-corruption
  - jpeg
  - qualcomm
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2025-47390
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-47390
  - https://docs.qualcomm.com/product/publicresources/securitybulletin/april-2026-bulletin.html
rules:
  - title: Detect Suspicious Process Calling IOCTL related to JPEG Driver
    description: Detects processes potentially attempting to exploit the JPEG driver via IOCTL calls
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Qualcomm JPEG Driver Loading
    description: Detects the loading of the Qualcomm JPEG driver, which might indicate vulnerable systems.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - image_load
      - windows
rules_count: 2
---

CVE-2025-47390 describes a memory corruption vulnerability found in the JPEG driver related to the preprocessing of IOCTL requests. This vulnerability, reported by Qualcomm, could allow a local attacker to potentially corrupt memory leading to a crash or arbitrary code execution. This vulnerability is documented in the Qualcomm Security Bulletin for April 2026. Successful exploitation of this issue could lead to denial of service, local privilege escalation, or information disclosure, impacting…
