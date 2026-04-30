---
title: ImageMagick XML Bomb Denial-of-Service Vulnerability (CVE-2026-33908)
slug: 2026-04-imagemagick-dos
description: ImageMagick versions prior to 7.1.2-19 and 6.9.13-44 are susceptible to a denial-of-service (DoS) attack due to unbounded recursion during XML parsing, potentially leading to stack exhaustion.
date: "2026-04-13T22:18:02Z"
severities:
  - medium
type: advisory
types:
  - advisory
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

ImageMagick is a widely used open-source software suite for displaying, converting, and editing raster image and vector image files. A critical vulnerability, identified as CVE-2026-33908, affects versions before 7.1.2-19 and 6.9.13-44. This vulnerability stems from the lack of depth limit during recursive processing of XML files via the `DestroyXMLTree()` function. An attacker can exploit this by crafting a malicious XML file with deeply nested structures. When ImageMagick parses this file, the recursive function exhausts stack memory, leading to a denial-of-service condition. Successful exploitation can disrupt services relying on ImageMagick, impacting image processing workflows. The vulnerability was addressed in versions 6.9.13-44 and 7.1.2-19.

## Attack Chain

1. An attacker crafts a malicious XML file with deeply nested elements.
2. The attacker delivers the crafted XML file to a system running a vulnerable version of ImageMagick (e.g., via upload, network share, or email attachment).
3. A user or automated process triggers ImageMagick to process the malicious XML file using command-line tools such as `convert` or through a web application using an ImageMagick library.
4. ImageMagick begins parsing the XML file and calls the `DestroyXMLTree()` function to free memory.
5. The `DestroyXMLTree()` function recursively traverses the XML tree without a depth limit.
6. Due to the deeply nested structure, the recursive calls consume excessive stack memory.
7. Stack memory is exhausted, leading to a stack overflow.
8. The ImageMagick process crashes, resulting in a denial-of-service condition.

## Impact

Successful exploitation of CVE-2026-33908 leads to a denial-of-service condition on the affected system. Services relying on ImageMagick for image processing become unavailable, potentially disrupting critical workflows. The CVSS v3.1 base score for this vulnerability is 7.5, indicating a high potential impact on system availability. The number of affected systems depends on the prevalence of vulnerable ImageMagick versions within an organization's infrastructure.

## Recommendation

*   Upgrade ImageMagick to version 7.1.2-19 or 6.9.13-44 or later to remediate CVE-2026-33908.
*   Implement file size limits and input validation for XML files processed by ImageMagick to mitigate the risk of malicious file uploads.
*   Deploy the Sigma rule `ImageMagick_XML_Crash` to detect potential exploitation attempts by monitoring for ImageMagick process crashes.
*   Monitor web server logs for unusual patterns of requests with large XML file uploads to identify potential attackers.
*   Enable process crash reporting on systems running ImageMagick to facilitate incident response and investigation.
