---
title: Supsystic Digital Publications Path Traversal and Stored XSS Vulnerability (CVE-2020-37245)
slug: 2026-05-supsystic-path-traversal-xss
description: Supsystic Digital Publications 1.6.9 contains a path traversal vulnerability in the Folder input field, allowing attackers to access sensitive files, and a stored XSS vulnerability due to improper input sanitization, leading to arbitrary script execution in the context of affected users (CVE-2020-37245).
date: "2026-05-16T16:19:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - xss
  - wordpress
  - plugin
vendors:
  - Supsystic
products:
  - Digital Publications by Supsystic 1.6.9
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2020-37245
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2020-37245
  - https://downloads.wordpress.org/plugin/digital-publications-by-supsystic.1.6.9.zip
  - https://supsystic.com/
  - https://www.exploit-db.com/exploits/49542
  - https://www.vulncheck.com/advisories/wordpress-plugin-supsystic-digital-publications-path-traversal-xss
rules:
  - title: Detect Supsystic Path Traversal
    description: Detects CVE-2020-37245 exploitation - Path traversal attempts in Supsystic Digital Publications plugin by searching for directory traversal sequences in HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Supsystic XSS Attempt
    description: Detects attempts to inject malicious JavaScript code into Supsystic Digital Publications plugin settings via HTTP requests.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - webserver
rules_count: 2
---

Supsystic Digital Publications version 1.6.9 is a WordPress plugin that suffers from both a path traversal and a stored cross-site scripting (XSS) vulnerability. The path traversal, identified as CVE-2020-37245, is located in the 'Folder' input field and allows unauthenticated attackers to access arbitrary files outside of the web root by injecting directory traversal sequences (e.g., ../). The plugin also fails to properly sanitize input fields within publication settings, specifically 'Area Width' and 'Publication Width', leading to stored XSS. Successful exploitation allows an attacker to execute arbitrary JavaScript code in the context of other users who view or edit the publications, potentially leading to session hijacking, defacement, or further malicious actions.

## Attack Chain

1. An attacker identifies a vulnerable Supsystic Digital Publications 1.6.9 installation.
2. The attacker crafts a malicious HTTP request to exploit the path traversal vulnerability by injecting directory traversal sequences in the `Folder` input field.
3. The server processes the request without proper validation, allowing the attacker to read arbitrary files outside the web root.
4. Alternatively, the attacker injects malicious JavaScript code into the 'Area Width' or 'Publication Width' parameters within the publication settings.
5. The server stores the unsanitized JavaScript code in the WordPress database.
6. A legitimate user views or edits the publication containing the injected XSS payload.
7. The user's browser executes the malicious JavaScript code, potentially stealing cookies or redirecting to a malicious site.
8. The attacker leverages the stolen session cookie or the ability to inject content to further compromise the WordPress site.

## Impact

Successful exploitation of the path traversal vulnerability (CVE-2020-37245) allows an attacker to read sensitive files on the server, potentially exposing credentials, configuration files, or other confidential information. The stored XSS vulnerability allows attackers to inject malicious scripts that execute in the context of other users, potentially leading to account takeover, data theft, or defacement of the website. This can impact any WordPress website running the vulnerable version of the plugin until it's patched or removed. The CVSS v3.1 base score for CVE-2020-37245 is 7.5, indicating a high severity vulnerability.

## Recommendation

*   Upgrade to a patched version of Supsystic Digital Publications that addresses the path traversal and XSS vulnerabilities.
*   Apply input validation and sanitization to all user-supplied input, especially in publication settings, to prevent XSS attacks.
*   Implement proper access controls and file permission restrictions to limit the impact of path traversal vulnerabilities.
*   Monitor web server logs for suspicious activity, such as requests containing directory traversal sequences, to detect potential exploitation attempts.
*   Deploy the Sigma rule `Detect Supsystic Path Traversal` to identify exploitation attempts in web server logs.
*   Deploy the Sigma rule `Detect Supsystic XSS Attempt` to detect potential attempts to inject malicious Javascript into publication parameters.
