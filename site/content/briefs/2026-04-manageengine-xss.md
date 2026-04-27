---
title: ManageEngine Exchange Reporter Plus Stored XSS Vulnerability
slug: 2026-04-manageengine-xss
description: Zohocorp ManageEngine Exchange Reporter Plus versions before 5802 are vulnerable to Stored XSS in the Distribution Lists report, allowing attackers to inject malicious scripts.
date: "2026-04-03T11:17:05Z"
severities:
  - medium
tags:
  - xss
  - vulnerability
  - manageengine
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-28754
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-28754
  - https://www.manageengine.com/products/exchange-reports/advisory/CVE-2026-28754.html
rules:
  - title: Detect Suspicious URI Access to Distribution List Reports
    description: Detects suspicious access attempts to the Distribution List report URI, which could indicate XSS exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious URI Access to Distribution List Reports Using Base64 Encoding
    description: Detects suspicious access attempts to the Distribution List report URI using base64 encoding, which could indicate XSS exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Zohocorp ManageEngine Exchange Reporter Plus versions prior to 5802 are susceptible to a Stored Cross-Site Scripting (XSS) vulnerability within the Distribution Lists report. This flaw allows an attacker with low privileges to inject malicious JavaScript code into the report. When other users view the compromised report, the injected script executes, potentially leading to session hijacking, sensitive data theft, or unauthorized administrative actions. The vulnerability stems from insufficient…
