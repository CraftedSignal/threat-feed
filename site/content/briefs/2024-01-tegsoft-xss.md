---
title: Tegsoft Online Support Application Reflected XSS Vulnerability (CVE-2025-14320)
slug: 2024-01-tegsoft-xss
description: CVE-2025-14320 is a reflected cross-site scripting (XSS) vulnerability in Tegsoft Online Support Application versions V3 through 31122025, allowing attackers to inject arbitrary web scripts into user browsers.
date: "2026-05-04T09:15:59Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - xss
  - reflected-xss
  - cve-2025-14320
vendors:
  - Tegsoft
products:
  - Online Support Application (V3 through 31122025)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-14320
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-14320
  - https://www.usom.gov.tr/bildirim/tr-26-0142
rules:
  - title: Detect Reflected XSS Attempt via GET Request
    description: Detects potential reflected XSS attempts by identifying suspicious patterns in GET request parameters.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1059.001
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Reflected XSS Attempt via POST Request
    description: Detects potential reflected XSS attempts by identifying suspicious patterns in POST request bodies.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1059.001
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A reflected cross-site scripting (XSS) vulnerability, identified as CVE-2025-14320, exists within the Tegsoft Management and Information Services Trade Limited Company Online Support Application. This vulnerability affects versions V3 through 31122025. An attacker can exploit this vulnerability by injecting malicious scripts into a web page, which is then reflected back to the user, leading to potential data theft, session hijacking, or website defacement. This vulnerability was reported by the Computer Emergency Response Team of the Republic of Turkey. Successful exploitation requires tricking a user into clicking a specially crafted link.

## Attack Chain

1.  Attacker crafts a malicious URL containing a JavaScript payload.
2.  The attacker distributes the crafted URL via email, social media, or other means.
3.  Unsuspecting user clicks the malicious URL.
4.  The user's browser sends a request to the vulnerable Tegsoft Online Support Application with the malicious script as a parameter.
5.  The Tegsoft application fails to properly sanitize the input.
6.  The application reflects the malicious script back to the user's browser within the HTML response.
7.  The user's browser executes the malicious script.
8.  The script can then perform actions such as stealing cookies, redirecting the user to a phishing site, or defacing the web page.

## Impact

Successful exploitation of this reflected XSS vulnerability can lead to the execution of arbitrary JavaScript code in the context of the victim's browser. This can result in session hijacking, where an attacker gains unauthorized access to the user's account. It can also lead to data theft, where sensitive information is stolen from the user's browser. Furthermore, the attacker can redirect the user to a phishing website or deface the Online Support Application, potentially impacting multiple users.

## Recommendation

*   Apply available patches or updates from Tegsoft to address CVE-2025-14320 on the Online Support Application.
*   Implement proper input validation and output encoding to prevent XSS vulnerabilities in the application based on CWE-79.
*   Deploy the provided Sigma rule to detect potential XSS attempts in web server logs.
*   Educate users about the dangers of clicking on suspicious links to mitigate the initial access vector.
