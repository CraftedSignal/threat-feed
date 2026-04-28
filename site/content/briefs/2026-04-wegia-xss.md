---
title: WeGIA Stored Cross-Site Scripting Vulnerability (CVE-2026-40286)
slug: 2026-04-wegia-xss
description: A stored Cross-Site Scripting (XSS) vulnerability exists in WeGIA versions prior to 3.6.10, allowing attackers to inject malicious scripts into the 'Member Name' field during member registration, leading to persistent execution upon user access.
date: "2026-04-17T21:16:34Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - xss
  - web-application
  - cve-2026-40286
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-40286
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40286
  - https://github.com/LabRedesCefetRJ/WeGIA/security/advisories/GHSA-42rc-rvrx-cmmw
rules:
  - title: Detect WeGIA XSS Attempt via HTTP Request
    description: Detects potential XSS attacks against WeGIA by searching for script tags or event handlers in HTTP request parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect WeGIA XSS Attempt via HTTP Request with Base64 Encoding
    description: Detects potential XSS attacks against WeGIA by searching for base64 encoded script tags or event handlers in HTTP request parameters.
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

WeGIA, a web manager for charitable institutions, is vulnerable to Stored Cross-Site Scripting (XSS) in versions prior to 3.6.10. The vulnerability, identified as CVE-2026-40286, resides in the 'Member Registration' function, specifically the 'Member Name' field. Attackers can inject malicious JavaScript code into this field. Because input is not properly validated and sanitized, the injected script is then stored in the application database.  Any user accessing the profile containing the malicious script will have the script executed in their browser.  This can lead to session hijacking, credential theft, or defacement. WeGIA version 3.6.10 addresses this vulnerability by implementing proper input sanitization. This vulnerability was reported on April 17, 2026.

## Attack Chain

1. An attacker identifies a vulnerable WeGIA instance running a version prior to 3.6.10.
2. The attacker accesses the 'Member Registration' (Cadastrar Sócio) page.
3. In the 'Member Name' (Nome Sócio) field, the attacker injects a malicious JavaScript payload (e.g., `<script>alert("XSS");</script>`).
4. The attacker submits the registration form.
5. The WeGIA application stores the malicious payload in the database without proper sanitization.
6. A legitimate user navigates to a page displaying the compromised 'Member Name' field, such as a member profile page.
7. The malicious JavaScript code is executed within the user's browser.
8. The attacker achieves their objective, such as stealing cookies or redirecting the user to a malicious website.

## Impact

Successful exploitation of this XSS vulnerability could lead to a range of consequences, including account compromise, data theft, and website defacement. An attacker could steal session cookies and impersonate legitimate users, gaining unauthorized access to sensitive information.  Due to the vulnerability residing in a web application, impact is limited to the users of the application, potentially exposing sensitive information and allowing threat actors the ability to modify the application.

## Recommendation

*   Upgrade WeGIA installations to version 3.6.10 or later to remediate CVE-2026-40286.
*   Implement input validation and sanitization on all user-supplied data, especially in the 'Member Name' field, to prevent XSS attacks.
*   Deploy the Sigma rule `title: "Detect WeGIA XSS Attempt via HTTP Request"` to detect potential XSS payloads in HTTP requests.
*   Enable web server logging and monitor for suspicious activity, such as unusual characters or script tags in HTTP request parameters, to identify potential XSS attempts.
