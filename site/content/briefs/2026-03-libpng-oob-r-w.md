---
title: LIBPNG Out-of-Bounds Read/Write Vulnerability in Neon Optimization (CVE-2026-33636)
slug: 2026-03-libpng-oob-r-w
description: An out-of-bounds read and write vulnerability in LIBPNG's ARM/AArch64 Neon-optimized palette expansion path (CVE-2026-33636) allows attackers to potentially achieve denial-of-service or arbitrary code execution by crafting malicious PNG images.
date: "2026-03-27T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - libpng
  - png
  - oob
  - CVE-2026-33636
  - vulnerability
  - defense-evasion
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33636
rules:
  - title: LIBPNG Crash Due to CVE-2026-33636
    description: Detects potential exploitation of CVE-2026-33636 by monitoring for crashes in processes using libpng, specifically when processing PNG images.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
  - title: Suspicious Process Loading LIBPNG
    description: Detects processes loading libpng from unusual locations, which could indicate exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1190
    data_sources:
      - image_load
      - linux
rules_count: 2
---

CVE-2026-33636 describes an out-of-bounds read and write vulnerability within the LIBPNG library, specifically affecting versions 1.6.36 through 1.6.55. The vulnerability resides in the ARM/AArch64 Neon-optimized palette expansion path. This flaw occurs when expanding 8-bit paletted rows to RGB or RGBA formats. The Neon loop processes a final partial chunk of data without properly validating that sufficient input pixels remain. This lack of validation leads to out-of-bounds memory access during…
