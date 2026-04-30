---
title: GLPI Cross-Site Scripting Vulnerability (CVE-2026-25932)
slug: 2026-04-glpi-xss
description: CVE-2026-25932 is a cross-site scripting vulnerability in GLPI versions 0.60 to before 10.0.24, where an authenticated technician user can store a malicious XSS payload within supplier fields, potentially leading to arbitrary code execution in the context of other users' browsers.
date: "2026-04-06T15:17:06Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - xss
  - glpi
  - cve-2026-25932
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-25932
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-25932
  - https://github.com/glpi-project/glpi/security/advisories/GHSA-m627-945g-x7xh
rules:
  - title: Detect GLPI Suspicious HTTP Referer
    description: Detects requests to GLPI with a suspicious HTTP Referer header, potentially indicating XSS attacks.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect GLPI XSS Payload in HTTP Request
    description: Detects HTTP requests to GLPI containing common XSS payload patterns in the query string.
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

CVE-2026-25932 is a stored cross-site scripting (XSS) vulnerability affecting GLPI, a free asset and IT management software package. The vulnerability exists in versions 0.60 up to, but not including, 10.0.24. An authenticated technician user, with the necessary privileges, can inject a malicious XSS payload into the supplier fields within the GLPI application. This payload is then stored in the database and executed when other users with access to the affected supplier data view the information. This can lead to session hijacking, defacement of the GLPI interface, or other malicious actions performed in the context of the victim user. Successful exploitation requires a valid technician account and user interaction. The vulnerability is patched in GLPI version 10.0.24.

## Attack Chain

1.  Attacker authenticates to GLPI as a technician user with sufficient privileges.
2.  Attacker navigates to the supplier management section of the GLPI interface.
3.  Attacker identifies a supplier field vulnerable to XSS (e.g., name, address, contact).
4.  Attacker injects a malicious JavaScript payload into the chosen supplier field.
5.  The malicious payload is stored in the GLPI database.
6.  A different user (e.g., administrator or another technician) accesses the supplier record containing the XSS payload through the GLPI web interface.
7.  The GLPI application retrieves the supplier data from the database and renders it in the user's browser.
8.  The malicious JavaScript code is executed within the context of the victim user's browser, enabling the attacker to perform actions such as stealing cookies, redirecting the user, or modifying data within GLPI.

## Impact

Successful exploitation of CVE-2026-25932 can allow an attacker to execute arbitrary JavaScript code within the context of other GLPI users' browsers. This can result in session hijacking, where the attacker gains unauthorized access to the victim's GLPI account. The attacker may also be able to deface the GLPI interface or modify data within the application. The CVSS v3.1 score of 7.2 indicates a high potential impact. While the precise number of vulnerable installations is unknown, any organization using GLPI versions 0.60 to 10.0.23 is potentially affected.

## Recommendation

*   Upgrade GLPI to version 10.0.24 or later to patch CVE-2026-25932.
*   Deploy the Sigma rule "Detect GLPI Suspicious HTTP Referer" to identify potential exploitation attempts targeting GLPI.
*   Implement strict input validation and output encoding measures to prevent XSS vulnerabilities in GLPI.
*   Review GLPI user permissions and roles to minimize the impact of potential XSS attacks.
*   Monitor web server logs for suspicious activity related to GLPI, such as unusual requests or error messages.
