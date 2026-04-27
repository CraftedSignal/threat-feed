---
title: Adobe Connect Reflected XSS Vulnerability (CVE-2026-27245)
slug: 2024-02-adobe-connect-xss
description: Adobe Connect versions 2025.3, 12.10, and earlier are vulnerable to a reflected Cross-Site Scripting (XSS) attack, enabling attackers to execute malicious JavaScript in a victim's browser by enticing them to visit a crafted URL.
date: "2026-04-14T18:16:55Z"
severities:
  - high
tags:
  - xss
  - adobe-connect
  - cve-2026-27245
  - reflected-xss
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-27245
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27245
  - https://helpx.adobe.com/security/products/connect/apsb26-37.html
ioc_counts:
  email: 1
  url: 2
rules:
  - title: Detect Adobe Connect XSS Attempt via URI
    description: Detects potential reflected XSS attempts targeting Adobe Connect by looking for JavaScript-like syntax in the URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Reflected XSS Payloads in URI
    description: This rule detects generic reflected XSS payloads in web server URIs.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A reflected Cross-Site Scripting (XSS) vulnerability, identified as CVE-2026-27245, affects Adobe Connect versions 2025.3, 12.10, and earlier. This vulnerability allows an attacker to inject malicious JavaScript code into a user's browser by convincing them to click on a specially crafted URL. When the victim visits the malicious URL, the injected script executes within their browser session, potentially enabling the attacker to steal cookies, redirect the user to a malicious website, or deface…
