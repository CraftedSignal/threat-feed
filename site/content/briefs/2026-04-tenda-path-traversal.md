---
title: Tenda i6 Path Traversal Vulnerability (CVE-2026-6024)
slug: 2026-04-tenda-path-traversal
description: A path traversal vulnerability (CVE-2026-6024) exists in the R7WebsSecurityHandler function of the HTTP Handler component in Tenda i6 1.0.0.7(2204), allowing remote attackers to access sensitive files or execute arbitrary code due to improper input validation.
date: "2026-04-10T06:23:22Z"
severities:
  - high
tags:
  - path-traversal
  - tenda
  - cve-2026-6024
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6024
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6024
  - https://github.com/Litengzheng/vuldb_new/blob/main/M3/vul_84/README.md
  - https://vuldb.com/vuln/356600
rules:
  - title: Detect Path Traversal Attempts via HTTP Requests
    description: Detects HTTP requests containing common path traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Access to Sensitive Files via Path Traversal
    description: Detects attempts to access sensitive files (e.g., /etc/passwd) via path traversal.
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

A critical path traversal vulnerability, identified as CVE-2026-6024, has been discovered in Tenda i6 firmware version 1.0.0.7(2204). The flaw resides within the `R7WebsSecurityHandler` function of the HTTP Handler component. This vulnerability allows a remote attacker to bypass security restrictions and access files or directories outside of the intended web server root. The vulnerability was reported in April 2026 and is considered exploitable because a proof-of-concept exploit is publicly…
