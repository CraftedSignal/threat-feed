---
title: CubeCart < 6.7.0 Unauthenticated Reflected Cross-Site Scripting (XSS)
slug: 2026-05-cubecart-xss
description: CubeCart versions before 6.7.0 are vulnerable to reflected cross-site scripting (XSS), allowing an unauthenticated attacker to inject malicious JavaScript payloads via the search functionality, which will be executed in the context of the victim's browser.
date: "2026-05-29T06:31:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - reflected-xss
  - web-application
  - cubecart
vendors:
  - CubeCart
products:
  - CubeCart < 6.7.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-44376
    cvss: 6.1
    epss: 0.00031
references:
  - https://www.exploit-db.com/exploits/52588
  - CVE-2026-44376
rules:
  - title: Detect CubeCart XSS Attempt via Search
    description: Detects CVE-2026-44376 exploitation - XSS attempts in CubeCart search queries.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CubeCart XSS Attempt via Catalogue
    description: Detects CVE-2026-44376 exploitation - XSS attempts in CubeCart catalogue queries.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A reflected cross-site scripting (XSS) vulnerability has been identified in CubeCart versions prior to 6.7.0. This vulnerability allows an unauthenticated attacker to inject arbitrary JavaScript code into the application via the search functionality. Successful exploitation of this vulnerability could allow an attacker to execute malicious scripts in a victim's browser when they visit a compromised CubeCart page. A public exploit (EDB-52588) demonstrating this vulnerability is available on Exploit-DB as of May 29, 2026. The vulnerability is located in the search or catalogue modules where user-supplied input is not properly sanitized before being output back to the user.

## Attack Chain

1. The attacker crafts a malicious URL containing a JavaScript payload in the `search[keywords]` parameter.
2. The attacker distributes the malicious URL to potential victims, typically via phishing or social engineering.
3. The victim clicks on the malicious URL, sending a request to the vulnerable CubeCart server.
4. The CubeCart server processes the request and includes the unsanitized `search[keywords]` value in the HTML response. The payload must contain a valid product name that returns only one result.
5. The victim's browser renders the HTML response, executing the injected JavaScript code.
6. The injected JavaScript code can perform various actions, such as stealing cookies, redirecting the user to a malicious website, or defacing the CubeCart website.
7. If the attacker steals the victim's session cookies, they can impersonate the victim and gain unauthorized access to their account.

## Impact

Successful exploitation of this XSS vulnerability could lead to various security breaches, including account takeover, defacement of the CubeCart website, and redirection of users to malicious websites. The severity is high due to the ease of exploitation (unauthenticated) and the potential for widespread impact. Given the availability of a public exploit, all CubeCart installations prior to version 6.7.0 are at immediate risk.

## Recommendation

*   Upgrade CubeCart to version 6.7.0 or later to patch CVE-2026-44376.
*   Deploy the Sigma rule "Detect CubeCart XSS Attempt via Search" to your SIEM to detect attempts to exploit this vulnerability via HTTP requests to the `/search` endpoint.
*   Monitor web server logs for suspicious requests containing `<script>` tags or other JavaScript-related keywords in the `search[keywords]` parameter.
*   Implement input validation and output encoding to prevent XSS vulnerabilities in CubeCart and other web applications.
