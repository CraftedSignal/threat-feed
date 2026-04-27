---
title: cgltf Integer Overflow Vulnerability in Sparse Accessor Validation
slug: 2026-03-cgltf-overflow
description: cgltf version 1.15 and prior contain an integer overflow vulnerability in the cgltf_validate() function when validating sparse accessors, allowing attackers to trigger out-of-bounds reads via crafted glTF/GLB files, leading to denial of service and potential memory disclosure.
date: "2026-03-23T16:16:48Z"
severities:
  - high
tags:
  - integer-overflow
  - denial-of-service
  - memory-disclosure
  - glTF
  - cgltf
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32845
rules:
  - title: Detect glTF Parsing Process Crash
    description: Detects a process crash associated with glTF or GLB file parsing using the cgltf library, potentially indicating exploitation of CVE-2026-32845.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - discovery
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect glTF Parsing Process Crash Linux
    description: Detects a process crash associated with glTF or GLB file parsing using the cgltf library, potentially indicating exploitation of CVE-2026-32845 on Linux.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - discovery
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

cgltf is a minimalist C library for loading glTF 2.0 files. Versions 1.15 and earlier are vulnerable to an integer overflow in the `cgltf_validate()` function. This vulnerability occurs during the validation of sparse accessors within glTF/GLB files. An attacker can exploit this by crafting malicious glTF/GLB files with specifically chosen size values that trigger integer overflows in arithmetic operations during sparse accessor validation. Successful exploitation leads to out-of-bounds reads…
