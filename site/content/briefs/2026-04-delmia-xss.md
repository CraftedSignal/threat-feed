---
title: DELMIA Factory Resource Manager Stored XSS Vulnerability (CVE-2025-10553)
slug: 2026-04-delmia-xss
description: A stored cross-site scripting (XSS) vulnerability in DELMIA Factory Resource Manager from Release 3DEXPERIENCE R2023x through Release 3DEXPERIENCE R2025x (CVE-2025-10553) allows attackers to execute arbitrary script code within a user's browser session.
date: "2026-03-31T09:18:30Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - xss
  - vulnerability
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-10553
    cvss: 8.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-10553
  - https://www.3ds.com/trust-center/security/security-advisories/cve-2025-10553
rules:
  - title: Detect DELMIA XSS Attempt via HTTP Request
    description: Detects potential attempts to exploit the DELMIA Factory Resource Manager XSS vulnerability (CVE-2025-10553) by looking for common XSS payloads in HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect DELMIA XSS via JavaScript keywords in URI
    description: Detects potential attempts to exploit the DELMIA Factory Resource Manager XSS vulnerability (CVE-2025-10553) by looking for javascript scheme in HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A stored cross-site scripting (XSS) vulnerability has been identified in DELMIA Factory Resource Manager, affecting versions from Release 3DEXPERIENCE R2023x through Release 3DEXPERIENCE R2025x. This vulnerability, assigned CVE-2025-10553, allows an attacker to inject malicious JavaScript code into the application. When a user interacts with the affected component, the injected script executes within their browser, potentially leading to session hijacking, sensitive data theft, or defacement of…
