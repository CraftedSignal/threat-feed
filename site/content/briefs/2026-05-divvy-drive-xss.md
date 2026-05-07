---
title: DivvyDrive Stored XSS Vulnerability
slug: 2026-05-divvy-drive-xss
description: DivvyDrive versions 4.8.2.9 before 4.8.3.2 are susceptible to stored cross-site scripting (XSS) due to improper neutralization of user-supplied input during web page generation, potentially allowing attackers to execute arbitrary JavaScript in a user's browser.
date: "2026-05-07T13:16:13Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - xss
  - stored-xss
  - web-application
vendors:
  - DivvyDrive Information Technologies Inc.
products:
  - DivvyDrive (4.8.2.9 < 4.8.3.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5784
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5784
  - https://siberguvenlik.gov.tr/guvenlik-bildirimleri/detay/tr-26-0182
rules:
  - title: Detect Potential XSS Payloads in Web Requests
    description: Detects common XSS payloads in web requests based on URI and request body analysis.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Script Tags in HTTP Request Headers
    description: Detects `<script>` tags present in HTTP request headers, which might indicate XSS attempts.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

DivvyDrive, a product of DivvyDrive Information Technologies Inc., is vulnerable to a stored cross-site scripting (XSS) vulnerability. This flaw, identified as CVE-2026-5784, arises from the improper neutralization of input during web page generation. Specifically, DivvyDrive versions from 4.8.2.9 before 4.8.3.2 are affected. An attacker can inject malicious scripts into the application, which are then stored and executed when other users interact with the affected content. This can lead to session hijacking, defacement, or redirection to malicious sites. The vulnerability was reported by the Computer Emergency Response Team of the Republic of Turkey.

## Attack Chain

1. An attacker identifies an input field within DivvyDrive (versions 4.8.2.9 to 4.8.3.1) that does not properly sanitize user-supplied data.
2. The attacker crafts a malicious payload containing JavaScript code.
3. The attacker injects the malicious payload into the vulnerable input field (e.g., a comment, profile field, or document name).
4. The application stores the attacker's payload in the database without proper sanitization.
5. A legitimate user accesses the page or feature where the malicious payload is stored and displayed.
6. The user's web browser executes the attacker's JavaScript code.
7. The malicious script can perform actions such as stealing the user's session cookies.
8. The attacker uses the stolen cookies to impersonate the user and gain unauthorized access to their account.

## Impact

Successful exploitation of this stored XSS vulnerability (CVE-2026-5784) in DivvyDrive could allow an attacker to execute arbitrary JavaScript code in the context of other users' browsers. This could lead to account compromise, session hijacking, defacement of the DivvyDrive instance, or redirection of users to malicious websites. The CVSS v3.1 base score is rated as 8.8 (High), indicating a significant risk.

## Recommendation

*   Upgrade DivvyDrive to version 4.8.3.2 or later to remediate the XSS vulnerability (CVE-2026-5784).
*   Deploy the provided Sigma rule to monitor for suspicious web requests containing common XSS payloads.
*   Implement robust input validation and output encoding mechanisms to prevent XSS attacks.
*   Regularly review and update security practices to mitigate the risk of similar vulnerabilities.
