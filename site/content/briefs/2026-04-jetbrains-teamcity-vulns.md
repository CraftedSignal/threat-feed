---
title: JetBrains TeamCity Authentication Bypass and Path Traversal Vulnerabilities
slug: 2026-04-jetbrains-teamcity-vulns
description: Unpatched JetBrains TeamCity servers are being actively exploited via an authentication bypass (CVE-2024-27198) and path traversal vulnerability (CVE-2024-27199), allowing attackers to perform administrative actions and potentially conduct supply-chain attacks.
date: "2026-04-22T10:00:00Z"
severities:
  - critical
exploited: true
tags:
  - teamcity
  - vulnerability
  - authentication bypass
  - path traversal
  - supply-chain
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2024-27198
    cvss: 9.8
    epss: 0.93047
  - id: CVE-2024-27199
    cvss: 7.3
    epss: 0.91011
references:
  - https://ccb.belgium.be/advisories/warning-authentication-bypass-and-path-traversal-vulnerabilities-jetbrains-teamcity
  - https://nvd.nist.gov/vuln/detail/CVE-2024-27198
  - https://nvd.nist.gov/vuln/detail/CVE-2024-27199
  - https://www.cisa.gov/news-events/alerts/2026/04/20/cisa-adds-eight-known-exploited-vulnerabilities-catalog
  - https://www.jetbrains.com/privacy-security/issues-fixed/
rules:
  - title: Detect TeamCity Authentication Bypass Attempt
    description: Detects attempts to exploit CVE-2024-27198 by identifying suspicious requests that bypass authentication in JetBrains TeamCity.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1555.004
    data_sources:
      - webserver
      - linux
  - title: Detect TeamCity Path Traversal Attempt
    description: Detects potential path traversal attempts (CVE-2024-27199) in JetBrains TeamCity by identifying requests containing directory traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - resource_development
    techniques:
      - T1190
      - T1588.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

JetBrains TeamCity, a CI/CD software platform, is vulnerable to CVE-2024-27198, an authentication bypass, and CVE-2024-27199, a path traversal vulnerability. These flaws affect TeamCity versions prior to 2023.11.4. Initially, there was no observed active exploitation. However, by March 7, 2024, widespread exploitation was detected following the public availability of proof-of-concept code. Attackers are actively exploiting these vulnerabilities to create new user accounts on publicly exposed…
