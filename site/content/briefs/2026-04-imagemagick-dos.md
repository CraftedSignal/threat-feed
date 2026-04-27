---
title: ImageMagick XML Bomb Denial-of-Service Vulnerability (CVE-2026-33908)
slug: 2026-04-imagemagick-dos
description: ImageMagick versions prior to 7.1.2-19 and 6.9.13-44 are susceptible to a denial-of-service (DoS) attack due to unbounded recursion during XML parsing, potentially leading to stack exhaustion.
date: "2026-04-13T22:18:02Z"
severities:
  - medium
tags:
  - dos
  - imagemagick
  - xml
  - cve-2026-33908
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-33908
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33908
rules:
  - title: ImageMagick XML Crash
    description: Detects crashes of the ImageMagick process, potentially caused by XML bomb attacks
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - windows
  - title: ImageMagick Large XML File Processing
    description: Detects ImageMagick processing unusually large XML files
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

ImageMagick is a widely used open-source software suite for displaying, converting, and editing raster image and vector image files. A critical vulnerability, identified as CVE-2026-33908, affects versions before 7.1.2-19 and 6.9.13-44. This vulnerability stems from the lack of depth limit during recursive processing of XML files via the `DestroyXMLTree()` function. An attacker can exploit this by crafting a malicious XML file with deeply nested structures. When ImageMagick parses this file…
