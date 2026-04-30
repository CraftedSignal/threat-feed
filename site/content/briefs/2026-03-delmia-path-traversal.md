---
title: DELMIA Factory Resource Manager Path Traversal Vulnerability (CVE-2025-10559)
slug: 2026-03-delmia-path-traversal
description: CVE-2025-10559 is a path traversal vulnerability in DELMIA Factory Resource Manager, affecting versions 3DEXPERIENCE R2023x through R2025x, which allows an attacker with low privileges to read or write files in specific directories on the server, potentially leading to information disclosure or code execution.
date: "2026-03-31T09:16:21Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - path-traversal
  - vulnerability
  - delmia
  - cve-2025-10559
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-10559
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-10559
  - https://www.3ds.com/trust-center/security/security-advisories/cve-2025-10559
ioc_counts:
  email: 1
rules:
  - title: Detect Path Traversal Attempts in DELMIA Factory Resource Manager
    description: Detects potential path traversal attacks against DELMIA Factory Resource Manager by identifying suspicious file path patterns in web server logs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect File Access Outside Webroot via Path Traversal
    description: Detects access to sensitive files (e.g., /etc/passwd) using path traversal techniques.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2025-10559 is a critical path traversal vulnerability found in the DELMIA Factory Resource Manager, impacting versions from 3DEXPERIENCE R2023x to R2025x. This vulnerability allows an attacker with low-level privileges (authenticated user) to manipulate file paths and potentially read or write arbitrary files within specific directories on the server. This can be exploited to read sensitive configuration files, overwrite critical system files, or potentially achieve remote code execution…
