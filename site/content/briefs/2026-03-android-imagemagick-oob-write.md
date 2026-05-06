---
title: Android-ImageMagick7 Out-of-Bounds Write Vulnerability (CVE-2026-33854)
slug: 2026-03-android-imagemagick-oob-write
description: An unauthenticated, remote attacker can exploit an out-of-bounds write vulnerability (CVE-2026-33854) in MolotovCherry Android-ImageMagick7 versions before 7.1.2-10 by enticing a user to open a malicious image, potentially leading to arbitrary code execution.
date: "2026-03-24T06:16:22Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve
  - out-of-bounds write
  - android
  - imagemagick
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33854
  - https://github.com/MolotovCherry/Android-ImageMagick7/pull/184
rules:
  - title: Detect ImageMagick Image Processing via HTTP
    description: Detects requests to ImageMagick processing endpoints that could be indicative of exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect pull request to Android-ImageMagick7 repo
    description: Detects network requests to the specific pull request associated with the vulnerability fix, potentially indicating reconnaissance.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595.002
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-33854 is an out-of-bounds write vulnerability affecting MolotovCherry Android-ImageMagick7 versions prior to 7.1.2-10.  This vulnerability stems from improper bounds checking within the image processing logic. The Government Technology Agency of Singapore Cyber Security Group (GovTech CSG) reported this vulnerability. Successful exploitation could lead to a denial of service, information disclosure, or potentially arbitrary code execution on the affected device. Due to the widespread…
