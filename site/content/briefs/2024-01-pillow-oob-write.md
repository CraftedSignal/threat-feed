---
title: Pillow Out-of-Bounds Write Vulnerability in PSD Processing (CVE-2026-42311)
slug: 2024-01-pillow-oob-write
description: Pillow versions 10.3.0 through 12.1.1 are vulnerable to an out-of-bounds write in PSD image decoding/encoding due to an integer overflow when computing tile extent sums, potentially leading to arbitrary code execution.
date: "2026-05-04T20:20:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - pillow
  - oob-write
  - integer-overflow
  - psd
  - memory-corruption
vendors:
  - Python
products:
  - Pillow (>= 10.3.0, < 12.2.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2026-25990
    cvss: 7.5
    epss: 0.00014
references:
  - https://github.com/advisories/GHSA-pwv6-vv43-88gr
  - https://github.com/python-pillow/Pillow/pull/9520
rules:
  - title: Detect Pillow PSD Processing
    description: Detects the execution of Python scripts that process PSD files, which may indicate exploitation attempts against Pillow vulnerabilities.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Pillow PSD Decode/Encode Files
    description: Detects write events to decode.c or encode.c which may indicate exploitation attempts against Pillow vulnerabilities.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Pillow, a popular Python image processing library, is vulnerable to an out-of-bounds write vulnerability (CVE-2026-42311) when processing PSD files. Specifically, versions 10.3.0 up to 12.1.1 contain a flaw in how they handle tile extents in PSD image decoding and encoding. The vulnerability arises from an integer overflow when calculating tile extent sums, which bypasses intended bounds checks. This allows a specially crafted PSD image with malicious tile dimensions to trigger an out-of-bounds write in `src/decode.c` and `src/encode.c`. Successful exploitation could lead to memory corruption, resulting in a crash or, more critically, arbitrary code execution. The issue was initially addressed in version 12.1.1 (CVE-2026-25990) but the fix was incomplete due to the integer overflow issue. The vulnerability is resolved in Pillow version 12.2.0 by avoiding the addition of extents before comparison.

## Attack Chain

1. An attacker crafts a malicious PSD image file with specific tile dimensions designed to trigger an integer overflow.
2. The victim's application, using a vulnerable version of Pillow (10.3.0 - 12.1.1), attempts to process the malicious PSD file.
3. During PSD image decoding/encoding, Pillow calculates the tile extent sums.
4. Due to the crafted tile dimensions, the integer overflow occurs, causing the calculated extent sums to wrap around.
5. The wrapped-around extent sums bypass the bounds checks implemented in Pillow.
6. An out-of-bounds write operation occurs in `src/decode.c` or `src/encode.c`, corrupting memory.
7. The memory corruption leads to either a crash of the application or, in a more severe scenario, allows the attacker to inject and execute arbitrary code.
8. The attacker gains control of the affected system, potentially leading to further malicious activities like data exfiltration or lateral movement.

## Impact

Successful exploitation of this vulnerability can lead to denial of service (application crash) or, more critically, arbitrary code execution. If an attacker can execute code on a system, they could potentially gain complete control of the system. This could lead to data theft, system compromise, and further propagation of attacks. The vulnerability affects any application that uses the Pillow library to process PSD files, potentially impacting a wide range of software across various sectors.

## Recommendation

*   Upgrade Pillow to version 12.2.0 or later to remediate CVE-2026-42311, which corrects the integer overflow issue and prevents the out-of-bounds write.
*   Monitor process creations for the execution of Python scripts (`python.exe`, `python3`) that process untrusted PSD files. Deploy the Sigma rule `Detect Pillow PSD Processing` to identify potentially malicious PSD processing activity.
