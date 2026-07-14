---
title: Denial-of-Service Vulnerability in Pillow EPS Parser (CVE-2026-59203)
slug: 2026-07-pillow-dos
description: A denial-of-service vulnerability, CVE-2026-59203, exists in the Python imaging library Pillow, affecting versions 12.0.0 through 12.2.0, where a specially crafted EPS file with a negative byte count in the `%%BeginBinary` directive can cause an infinite loop and resource exhaustion when processed by the `Image.open()` function, leading to application unresponsiveness.
date: "2026-07-14T20:43:50Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
cpes:
  - cpe:2.3:a:python:pillow:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - python
  - pillow
vendors:
  - Python
products:
  - Pillow 12.0.0
  - Pillow 12.1.0
  - Pillow 12.2.0
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Application or System Impairment
    evidence: Pillow's EPS parser in PIL/EpsImagePlugin.py accepts a negative byte count in the %%BeginBinary directive, allowing a crafted EPS file to cause Image.open() to seek backwards to the same directive and parse it repeatedly in an infinite loop.
    confidence_band: high
cves:
  - id: CVE-2026-59203
    cvss: 5.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-59203
  - https://github.com/python-pillow/Pillow/commit/03992618118b4a76b6163cd72ab5ecd684133b83
  - https://github.com/python-pillow/Pillow/pull/9708
  - https://github.com/python-pillow/Pillow/releases/tag/12.3.0
  - https://github.com/python-pillow/Pillow/security/advisories/GHSA-pg7v-jwj7-p798
---

CVE-2026-59203 describes a denial-of-service vulnerability affecting Pillow, a widely used Python imaging library, in versions 12.0.0 through 12.2.0. The flaw resides within the EPS parser (specifically in `PIL/EpsImagePlugin.py`), which improperly handles a negative byte count in the `%%BeginBinary` directive of an Encapsulated PostScript (EPS) file. An attacker can craft a malicious EPS file that, when processed by Pillow's `Image.open()` function, causes the parser to repeatedly seek backward and parse the same directive, leading to an infinite loop and resource exhaustion. This can render applications relying on Pillow unresponsive or crash them. The vulnerability was discovered by GitHub, Inc. and is addressed in Pillow version 12.3.0. No specific threat actors or active exploitation campaigns have been reported, but the broad usage of Pillow makes this a significant concern for applications processing untrusted image files.

## Attack Chain

1. An attacker creates a specially crafted Encapsulated PostScript (EPS) file.
2. The crafted EPS file is designed to include a negative byte count within the `%%BeginBinary` directive.
3. The victim's application, using Pillow versions 12.0.0 through 12.2.0, attempts to open and process this malicious EPS file via `Image.open()`.
4. Pillow's EPS parser (`PIL/EpsImagePlugin.py`) encounters the malformed `%%BeginBinary` directive.
5. Due to the negative byte count, the parser attempts to seek backwards within the file stream to the location of the same directive.
6. This incorrect seeking results in the parser entering an infinite loop, continuously parsing the same malformed directive.
7. The infinite loop consumes excessive CPU and memory resources, leading to a denial of service for the application and potentially the underlying system.

## Impact

Successful exploitation of CVE-2026-59203 leads to a denial of service (DoS) condition. Applications that use affected versions of Pillow (12.0.0 through 12.2.0) to process untrusted EPS files may become unresponsive, hang indefinitely, or crash entirely due to the infinite loop consuming all available CPU and memory resources. While no specific victim counts or targeted sectors are detailed, any organization processing user-supplied or external EPS images with vulnerable Pillow versions is at risk of application downtime and resource exhaustion, impacting service availability and operational continuity. This can disrupt services, degrade user experience, and require manual intervention to restore affected systems.

## Recommendation

* Patch CVE-2026-59203 on all systems using Pillow versions 12.0.0 through 12.2.0 by upgrading the `Pillow` library to version 12.3.0 or later.
* Implement robust input validation for EPS files processed by applications to prevent malformed data from reaching vulnerable Pillow versions.
