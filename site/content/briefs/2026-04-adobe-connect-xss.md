---
title: Adobe Connect Reflected XSS Vulnerability (CVE-2026-27243)
slug: 2026-04-adobe-connect-xss
description: Adobe Connect versions 2025.3, 12.10 and earlier are vulnerable to reflected Cross-Site Scripting (XSS), allowing an attacker to execute malicious JavaScript in a victim's browser by enticing them to visit a specially crafted URL.
date: "2026-04-15T12:00:00Z"
severities:
  - critical
tags:
  - adobe-connect
  - xss
  - cve-2026-27243
  - reflected-xss
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
cves:
  - id: CVE-2026-27243
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27243
  - https://helpx.adobe.com/security/products/connect/apsb26-37.html
ioc_counts:
  email: 1
  url: 1
rules:
  - title: Detect Adobe Connect XSS Attempt
    description: Detects potential reflected XSS attempts targeting Adobe Connect by identifying requests containing common XSS payloads in the URI query.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
  - title: Detect Adobe Connect Redirection to NVD
    description: Detects attempts to redirect users to the NVD website from Adobe Connect, potentially indicating an unauthorized frame window issue.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Adobe Connect versions 2025.3, 12.10, and earlier are susceptible to a reflected Cross-Site Scripting (XSS) vulnerability, identified as CVE-2026-27243. This flaw allows an attacker to inject and execute arbitrary JavaScript code within a user's browser session if the user visits a malicious URL. The vulnerability arises because the application fails to properly sanitize user-supplied input before reflecting it back to the user. Exploitation requires social engineering to convince a victim to…
