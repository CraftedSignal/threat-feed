---
title: ManageEngine Exchange Reporter Plus Stored XSS Vulnerability
slug: 2026-04-manageengine-xss
description: Zohocorp ManageEngine Exchange Reporter Plus versions before 5802 are vulnerable to Stored XSS in the Distribution Lists report, allowing attackers to inject malicious scripts.
date: "2026-04-03T11:17:05Z"
type: advisory
types:
  - advisory
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

Zohocorp ManageEngine Exchange Reporter Plus versions prior to 5802 are susceptible to a Stored Cross-Site Scripting (XSS) vulnerability within the Distribution Lists report. This flaw allows an attacker with low privileges to inject malicious JavaScript code into the report. When other users view the compromised report, the injected script executes, potentially leading to session hijacking, sensitive data theft, or unauthorized administrative actions. The vulnerability stems from insufficient input sanitization when generating the Distribution Lists report, a feature within the Exchange Reporter Plus application designed to provide insights into Exchange environments.

## Attack Chain

1. Attacker authenticates to ManageEngine Exchange Reporter Plus with low-privilege credentials.
2. Attacker navigates to the Distribution Lists report generation page.
3. Attacker crafts a malicious payload containing JavaScript code designed to execute upon rendering. This payload is injected via a field that contributes to the report.
4. The application stores the malicious payload without proper sanitization within the Distribution Lists report data.
5. A privileged user views the Distribution Lists report through the web interface.
6. The stored malicious JavaScript payload is rendered within the user's browser.
7. The script executes within the context of the user's session, potentially stealing cookies or other sensitive information.
8. The attacker leverages the stolen credentials or session to perform unauthorized actions within the ManageEngine Exchange Reporter Plus application, such as accessing sensitive reports or modifying configurations.

## Impact

Successful exploitation of this Stored XSS vulnerability allows an attacker to compromise user accounts and potentially gain administrative access to the ManageEngine Exchange Reporter Plus application. This can lead to unauthorized access to sensitive Exchange environment data, including email addresses, distribution list memberships, and other configuration details. Given the broad adoption of ManageEngine products, this vulnerability could impact numerous organizations relying on Exchange Reporter Plus for monitoring and reporting. The impact is magnified because the injected script is stored, affecting multiple users who view the compromised report.

## Recommendation

*   Upgrade ManageEngine Exchange Reporter Plus to version 5802 or later to patch CVE-2026-28754.
*   Deploy the Sigma rule `Detect Suspicious URI Access to Distribution List Reports` to identify potential exploitation attempts.
*   Implement input validation and sanitization on the Distribution Lists report generation page to prevent the injection of malicious scripts.
