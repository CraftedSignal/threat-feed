---
title: Adobe ColdFusion Path Traversal Vulnerability (CVE-2026-34619)
slug: 2026-04-coldfusion-path-traversal
description: A path traversal vulnerability (CVE-2026-34619) in Adobe ColdFusion versions 2023.18, 2025.6, and earlier allows an attacker to bypass security features and access unauthorized files or directories without user interaction.
date: "2026-04-15T12:00:00Z"
severities:
  - high
tags:
  - path-traversal
  - coldfusion
  - cve-2026-34619
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-34619
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34619
  - https://helpx.adobe.com/security/products/coldfusion/apsb26-38.html
rules:
  - title: Detect ColdFusion Path Traversal Attempts
    description: Detects potential path traversal attempts targeting Adobe ColdFusion servers by looking for '../' sequences in URI queries.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - windows|linux
  - title: Detect ColdFusion Path Traversal via Double Encoding
    description: Detects path traversal attempts in Adobe ColdFusion that may be obfuscated using double URL encoding.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - windows|linux
rules_count: 2
---

CVE-2026-34619 describes a path traversal vulnerability affecting Adobe ColdFusion versions 2023.18, 2025.6, and earlier. Disclosed on April 14, 2026, this vulnerability allows an attacker to bypass intended security restrictions and gain access to sensitive files and directories on the ColdFusion server. The vulnerability exists due to improper limitation of pathnames, and successful exploitation requires no user interaction, making it particularly dangerous. This issue could lead to the…
