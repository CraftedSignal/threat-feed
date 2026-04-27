---
title: Tenda i9 Path Traversal Vulnerability (CVE-2026-7036)
slug: 2026-04-tenda-path-traversal
description: CVE-2026-7036 is a path traversal vulnerability affecting the R7WebsSecurityHandlerfunction in the HTTP Handler component of Tenda i9 version 1.0.0.5(2204), allowing remote attackers to access sensitive files.
date: "2026-04-26T12:16:22Z"
severities:
  - high
tags:
  - cve-2026-7036
  - path-traversal
  - tenda
  - network
vendors:
  - Tenda
products:
  - i9
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7036
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7036
  - https://github.com/Litengzheng/vuldb_new/blob/main/M3/vul_80/README.md
  - https://vuldb.com/vuln/359616
rules:
  - title: Detect Tenda i9 Path Traversal Attempt
    description: Detects potential path traversal attempts targeting web servers using common traversal sequences
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Web Request to Sensitive Files
    description: Detects web requests for sensitive files, potentially indicating path traversal
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A path traversal vulnerability, identified as CVE-2026-7036, exists in Tenda i9 version 1.0.0.5(2204). Specifically, the vulnerability resides in the R7WebsSecurityHandlerfunction of the HTTP Handler component. This flaw allows a remote, unauthenticated attacker to potentially access sensitive files and directories on the affected device. The vulnerability was reported on 2026-04-26, and a public exploit is reportedly available, increasing the risk of exploitation. This poses a significant…
