---
title: Tenda i3 Path Traversal Vulnerability (CVE-2026-5841)
slug: 2026-04-tenda-path-traversal
description: A path traversal vulnerability (CVE-2026-5841) exists in the R7WebsSecurityHandler function of the HTTP Handler component in Tenda i3 version 1.0.0.6(2204), allowing a remote attacker to bypass authentication and potentially access sensitive files due to publicly available exploits.
date: "2026-04-09T05:16:06Z"
severities:
  - high
tags:
  - path-traversal
  - tenda
  - cve-2026-5841
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5841
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5841
  - https://github.com/MrXiaoFan/TendaVul/tree/main/tenda-i3-V1.0.0.6(2204)-R7WebsSecurityHandler-Authentication%20Bypass%20Issues
  - https://vuldb.com/submit/789935
  - https://vuldb.com/vuln/356297
  - https://vuldb.com/vuln/356297/cti
  - https://www.tenda.com.cn/
ioc_counts:
  email: 1
  url: 5
rules:
  - title: Detect Tenda i3 Path Traversal Attempts via Web Logs
    description: Detects path traversal attempts in HTTP requests targeting Tenda i3 devices, potentially exploiting CVE-2026-5841.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1133
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda i3 Path Traversal Attempts via Web Logs (Encoded)
    description: Detects path traversal attempts with URL encoded characters in HTTP requests targeting Tenda i3 devices, potentially exploiting CVE-2026-5841.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1133
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical path traversal vulnerability has been identified in Tenda i3 router firmware version 1.0.0.6(2204). The vulnerability, tracked as CVE-2026-5841, resides within the R7WebsSecurityHandler function of the HTTP Handler component. This flaw allows unauthenticated remote attackers to manipulate requests and potentially gain unauthorized access to sensitive files and directories on the device. The vulnerability is considered high risk due to the availability of public exploits, increasing…
