---
title: CPython Zipfile Module Vulnerability Allows File Manipulation
slug: 2026-03-cpython-zipfile-manipulation
description: A remote, anonymous attacker can exploit a vulnerability in the zipfile module of CPython to manipulate files on affected systems.
date: "2026-03-25T12:00:00Z"
severities:
  - medium
tags:
  - cpython
  - zipfile
  - file-manipulation
  - vulnerability
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-2230
rules:
  - title: Suspicious Process Creation After ZIP Archive Processing
    description: Detects suspicious processes spawned by Python interpreters after processing ZIP archives, potentially indicating exploitation of the zipfile vulnerability.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: File Modification After Zipfile Processing
    description: Detects modification of executables after zipfile processing, potentially indicating exploitation.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - file_event
      - windows
rules_count: 2
---

A vulnerability exists within the `zipfile` module of CPython, potentially allowing an unauthenticated remote attacker to manipulate files. The CERT-Bund vulnerability advisory, initially published on 2026-03-24, highlights this issue. While the specifics of the vulnerability and its exploitation are not detailed in the provided source material, the core concern is unauthorized modification of files through the manipulation of ZIP archives processed by the CPython `zipfile` module. This impacts…
