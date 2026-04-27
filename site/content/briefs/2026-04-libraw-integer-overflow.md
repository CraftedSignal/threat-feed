---
title: LibRaw Integer Overflow Vulnerability in deflate_dng_load_raw
slug: 2026-04-libraw-integer-overflow
description: CVE-2026-20884 is an integer overflow vulnerability in LibRaw's deflate_dng_load_raw function that leads to a heap buffer overflow when processing crafted DNG files.
date: "2026-04-07T15:17:35Z"
severities:
  - high
tags:
  - libraw
  - integer-overflow
  - heap-buffer-overflow
  - cve-2026-20884
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Defense Evasion
cves:
  - id: CVE-2026-20884
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20884
  - https://talosintelligence.com/vulnerability_reports/TALOS-2026-2364
rules:
  - title: Detect LibRaw Exploitation via DNG
    description: Detects suspicious process behavior when processing a DNG file, potentially indicating exploitation of LibRaw vulnerabilities such as CVE-2026-20884.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect LibRaw Memory Allocation Errors
    description: Detects potential memory allocation errors indicative of integer overflows, as seen in CVE-2026-20884, by monitoring for suspicious error messages in application logs.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-20884 describes an integer overflow vulnerability affecting LibRaw, specifically within the `deflate_dng_load_raw` function. This flaw resides in commit 8dc68e2 of the LibRaw library. The vulnerability can be exploited by providing a specially crafted DNG (Digital Negative) image file to an application using the affected LibRaw version. Successful exploitation results in a heap buffer overflow, potentially allowing an attacker to execute arbitrary code or cause a denial-of-service…
