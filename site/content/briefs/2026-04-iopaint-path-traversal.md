---
title: Sanster IOPaint Path Traversal Vulnerability (CVE-2026-5258)
slug: 2026-04-iopaint-path-traversal
description: A path traversal vulnerability (CVE-2026-5258) exists in Sanster IOPaint 1.5.3, allowing remote attackers to read arbitrary files by manipulating the filename argument in the _get_file function within the File Manager component.
date: "2026-04-01T07:16:02Z"
severities:
  - high
tags:
  - path traversal
  - cve-2026-5258
  - web application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5258
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5258
  - https://github.com/August829/CVEP/issues/11
  - https://vuldb.com/vuln/354448
rules:
  - title: Detect IOPaint Path Traversal Attempt
    description: Detects potential path traversal attempts targeting Sanster IOPaint by looking for suspicious URL encoded sequences in HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect IOPaint Path Traversal via GET Request
    description: Detects path traversal attempts in IOPaint through GET requests by identifying 'filename' parameter manipulation with path traversal sequences.
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

Sanster IOPaint version 1.5.3 is vulnerable to a path traversal flaw (CVE-2026-5258) within its File Manager component. The vulnerability resides in the `_get_file` function located in `iopaint/file_manager/file_manager.py`. By crafting a malicious request and manipulating the `filename` argument, an unauthenticated attacker can bypass directory restrictions and potentially read sensitive files on the server. Publicly available exploits exist, increasing the urgency for patching or mitigating…
