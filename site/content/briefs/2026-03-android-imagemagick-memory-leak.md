---
title: Android-ImageMagick7 Memory Leak Vulnerability (CVE-2026-33852)
slug: 2026-03-android-imagemagick-memory-leak
description: A missing release of memory vulnerability (CVE-2026-33852) in MolotovCherry Android-ImageMagick7 before version 7.1.2-11 can lead to a denial-of-service condition due to memory exhaustion.
date: "2026-03-24T07:16:07Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - cve
  - memory leak
  - denial of service
  - android
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33852
  - https://github.com/MolotovCherry/Android-ImageMagick7/pull/191
rules:
  - title: Detect Android ImageMagick Memory Growth
    description: Detects unusual memory growth of processes using Android-ImageMagick7, potentially indicating a memory leak.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Potential DoS via Repeated Image Processing
    description: Detects repeated process creations involving image processing tools, potentially indicating a DoS attempt.
    platform: sigma
    severity: low
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-33852 is a "Missing Release of Memory after Effective Lifetime" vulnerability affecting MolotovCherry Android-ImageMagick7 versions prior to 7.1.2-11. Discovered by the Government Technology Agency of Singapore Cyber Security Group (GovTech CSG), this memory leak can occur when processing specially crafted image files. An attacker could potentially exploit this vulnerability to cause a denial-of-service condition on a vulnerable Android device by repeatedly triggering the memory leak…
