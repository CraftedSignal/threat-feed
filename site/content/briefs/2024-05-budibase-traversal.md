---
title: Budibase Path Traversal Vulnerability in Plugin Upload
slug: 2024-05-budibase-traversal
description: A path traversal vulnerability exists in Budibase versions prior to 3.33.4, allowing attackers with Global Builder privileges to delete arbitrary directories and write arbitrary files via crafted plugin uploads.
date: "2026-04-03T16:16:41Z"
severities:
  - critical
tags:
  - path-traversal
  - vulnerability
  - budibase
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1566
    technique_name: Phishing
cves:
  - id: CVE-2026-35214
    cvss: 8.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35214
rules:
  - title: Detect Budibase Plugin Upload Path Traversal Attempt
    description: Detects attempts to exploit the path traversal vulnerability (CVE-2026-35214) in Budibase plugin uploads by identifying requests with directory traversal sequences in the filename.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1566
    data_sources:
      - webserver
      - linux
  - title: Detect Directory Deletion via rmSync
    description: Detects suspicious activity that could lead to directory deletion through rmSync following a path traversal.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1485
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Budibase, an open-source low-code platform, is vulnerable to a path traversal attack in versions prior to 3.33.4. This flaw resides in the plugin file upload endpoint (POST /api/plugin/upload), where the user-supplied filename is passed unsanitized to createTempFolder(). An attacker with Global Builder privileges can exploit this by crafting a multipart upload containing "../" sequences in the filename. This allows them to manipulate file paths, leading to arbitrary directory deletion via…
