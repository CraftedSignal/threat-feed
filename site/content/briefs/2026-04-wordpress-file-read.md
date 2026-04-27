---
title: Unlimited Elements for Elementor WordPress Plugin Arbitrary File Read (CVE-2026-4659)
slug: 2026-04-wordpress-file-read
description: The Unlimited Elements for Elementor plugin for WordPress is vulnerable to arbitrary file read due to insufficient path traversal sanitization, allowing authenticated attackers to read sensitive files from the WordPress host.
date: "2026-04-17T07:23:36Z"
severities:
  - high
tags:
  - wordpress
  - file-read
  - path-traversal
  - cve-2026-4659
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-4659
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4659
rules:
  - title: Detect WordPress Arbitrary File Read Attempt via Path Traversal
    description: Detects attempts to exploit path traversal vulnerabilities in WordPress plugins by monitoring HTTP requests for suspicious sequences.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect WordPress Arbitrary File Read Attempt via Long Path
    description: Detects attempts to exploit arbitrary file read vulnerabilities in WordPress plugins by monitoring HTTP requests for unusually long paths.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Unlimited Elements for Elementor plugin, versions 2.0.6 and earlier, contains an arbitrary file read vulnerability (CVE-2026-4659). This vulnerability stems from inadequate sanitization of path traversal sequences within the `URLtoRelative()` and `urlToPath()` functions, particularly when combined with the ability to enable debug output. The `URLtoRelative()` function inadequately strips the base URL without properly sanitizing path traversal characters (`../`). Successful exploitation…
