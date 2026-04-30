---
title: cgltf Integer Overflow Vulnerability in Sparse Accessor Validation
slug: 2026-03-cgltf-overflow
description: cgltf version 1.15 and prior contain an integer overflow vulnerability in the cgltf_validate() function when validating sparse accessors, allowing attackers to trigger out-of-bounds reads via crafted glTF/GLB files, leading to denial of service and potential memory disclosure.
date: "2026-03-23T16:16:48Z"
type: advisory
types:
  - advisory
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

cgltf is a minimalist C library for loading glTF 2.0 files. Versions 1.15 and earlier are vulnerable to an integer overflow in the `cgltf_validate()` function. This vulnerability occurs during the validation of sparse accessors within glTF/GLB files. An attacker can exploit this by crafting malicious glTF/GLB files with specifically chosen size values that trigger integer overflows in arithmetic operations during sparse accessor validation. Successful exploitation leads to out-of-bounds reads due to heap buffer over-reads in `cgltf_calc_index_bound()`. This results in a denial-of-service condition (application crash) and potentially leads to memory disclosure. Defenders should monitor applications parsing glTF/GLB files for unexpected crashes or abnormal memory access patterns.

## Attack Chain

1. The attacker crafts a malicious glTF or GLB file.
2. The crafted file contains a sparse accessor with attacker-controlled size values designed to cause an integer overflow.
3. The vulnerable application uses the cgltf library to parse the malicious glTF/GLB file.
4. The `cgltf_validate()` function is called to validate the glTF data, including the sparse accessor.
5. During sparse accessor validation, unchecked arithmetic operations occur with the attacker-controlled size values, resulting in an integer overflow.
6. The integer overflow leads to an incorrect calculation of the index bound in the `cgltf_calc_index_bound()` function.
7. `cgltf_calc_index_bound()` attempts to access a heap buffer using the incorrect index bound.
8. This results in an out-of-bounds read, causing a denial of service (application crash) or potentially exposing sensitive memory contents.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition, as the application parsing the malicious glTF/GLB file crashes. Furthermore, the out-of-bounds read could potentially expose sensitive information from the application's memory. The number of potential victims depends on the prevalence of applications using the vulnerable cgltf library to process potentially untrusted glTF/GLB files. Sectors affected could include any application that handles 3D models or scenes using the glTF format, such as game development, CAD software, and visualization tools.

## Recommendation

*   Upgrade to a patched version of the cgltf library that addresses CVE-2026-32845.
*   Implement input validation on glTF/GLB files before parsing them with cgltf to prevent malicious size values from reaching the vulnerable `cgltf_validate()` function.
*   Deploy the Sigma rule "Detect glTF Parsing Process Crash" to identify processes crashing while parsing glTF/GLB files, which can indicate exploitation attempts.
*   Enable process crash reporting to collect detailed information about crashes, including memory dumps, which can aid in identifying the root cause and potential memory disclosure.
