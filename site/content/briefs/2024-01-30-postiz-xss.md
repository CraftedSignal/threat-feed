---
title: Postiz File Upload Vulnerability Leads to Stored XSS (CVE-2026-40487)
slug: 2024-01-30-postiz-xss
description: An authenticated file upload validation bypass in Postiz prior to version 2.21.6 allows attackers to upload arbitrary HTML, SVG, or other executable file types by spoofing the `Content-Type` header, resulting in stored XSS and potential account takeover.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - file-upload
  - vulnerability
  - cve-2026-40487
  - postiz
vendors:
  - Postiz
products:
  - Postiz
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-40487
    cvss: 8.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40487
rules:
  - title: Detect Suspicious Postiz File Upload Content-Type Override
    description: Detects attempts to bypass file upload validation in Postiz by spoofing the Content-Type header.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious SVG File Uploads to Postiz
    description: Detects the upload of SVG files to Postiz which may contain malicious scripts.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Postiz, an AI-driven social media scheduling tool, is vulnerable to a file upload bypass that can be exploited by authenticated users. Prior to version 2.21.6, the application fails to properly validate uploaded files, allowing attackers to bypass intended restrictions. By spoofing the `Content-Type` header during the upload process, malicious actors can inject arbitrary HTML, SVG, or other executable file types onto the server. Nginx then serves these files with a Content-Type derived from their extension, such as `text/html` or `image/svg+xml`, which facilitates the execution of Stored Cross-Site Scripting (XSS) attacks within the application's context. This vulnerability enables session riding, account takeover, and potentially full compromise of other user accounts. The vulnerability is identified as CVE-2026-40487 and is resolved in version 2.21.6 of Postiz.

## Attack Chain

1. An attacker authenticates to the Postiz application with valid credentials.
2. The attacker crafts a malicious file (e.g., an HTML or SVG file) containing XSS payload.
3. The attacker intercepts the file upload request using a proxy (e.g., Burp Suite) or browser developer tools.
4. The attacker modifies the `Content-Type` header of the upload request to bypass the file validation. For example, an attacker could upload an HTML file but set the Content-Type to "image/jpeg".
5. The attacker sends the modified request to the Postiz server.
6. The Postiz server saves the file without proper validation and stores it on the server.
7. Nginx serves the malicious file with a Content-Type derived from the file extension, allowing the XSS payload to execute when another user accesses the file.
8. The XSS payload executes in the victim's browser, allowing the attacker to steal cookies, session tokens, or inject malicious content, leading to account takeover or further compromise.

## Impact

Successful exploitation of this vulnerability can lead to severe consequences, including session riding, account takeover, and full compromise of other users' accounts. An attacker could steal sensitive information, inject malicious scripts into the application, or deface the website. Given that Postiz is a social media scheduling tool, a successful attack could also be leveraged to spread misinformation or compromise connected social media accounts. The exact number of affected users is unknown, but all Postiz users prior to version 2.21.6 are potentially vulnerable.

## Recommendation

*   Upgrade Postiz to version 2.21.6 or later to patch CVE-2026-40487 immediately.
*   Deploy the Sigma rule "Detect Suspicious Postiz File Upload Content-Type Override" to detect attempts to exploit the vulnerability in real-time.
*   Monitor web server logs (category `webserver`) for unusual `Content-Type` headers during file uploads.
*   Implement strict file validation on the server-side, verifying file types based on their content rather than relying solely on the `Content-Type` header.
