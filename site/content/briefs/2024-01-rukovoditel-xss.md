---
title: Rukovoditel CRM Reflected XSS Vulnerability (CVE-2026-31845)
slug: 2024-01-rukovoditel-xss
description: A reflected XSS vulnerability in Rukovoditel CRM version 3.6.4 and earlier allows unauthenticated attackers to inject malicious JavaScript by reflecting the 'zd_echo' GET parameter, leading to potential session hijacking and account takeover.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rukovoditel
  - xss
  - cve-2026-31845
  - web-application
vendors:
  - Rukovoditel
products:
  - Rukovoditel CRM
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-31845
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-31845
rules:
  - title: Detect Rukovoditel CRM XSS Attempt
    description: Detects potential reflected XSS attempts targeting the Rukovoditel CRM Zadarma telephony API endpoint by looking for script tags or event handlers in the zd_echo parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Rukovoditel CRM Zadarma API Access
    description: Detects access to the Rukovoditel CRM Zadarma telephony API endpoint.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Rukovoditel CRM version 3.6.4 and earlier is vulnerable to a reflected cross-site scripting (XSS) attack. This vulnerability resides in the Zadarma telephony API endpoint (/api/tel/zadarma.php), where the application unsafely reflects the 'zd_echo' GET parameter directly into the HTTP response. This direct reflection, without proper sanitization, output encoding, or content-type restrictions, allows for the injection of arbitrary JavaScript code. An unauthenticated attacker can craft malicious URLs containing XSS payloads to exploit this vulnerability. The vulnerability was reported on 2026-04-11. Rukovoditel CRM is a web-based application, making this a potentially widespread vulnerability affecting any installations running the vulnerable version. Defenders should prioritize patching and implement mitigations to prevent exploitation. The vulnerability is fixed in version 3.7.

## Attack Chain

1.  The attacker crafts a malicious URL containing a JavaScript payload within the `zd_echo` GET parameter, targeting the `/api/tel/zadarma.php` endpoint. For example: `/api/tel/zadarma.php?zd_echo=<script>alert('XSS')</script>`.
2.  The attacker distributes the malicious URL via email, social media, or other channels to a potential victim.
3.  The victim, unaware of the malicious intent, clicks on the crafted URL.
4.  The victim's browser sends an HTTP GET request to the Rukovoditel CRM server, including the malicious `zd_echo` parameter.
5.  The Rukovoditel CRM server receives the request and, due to the vulnerability, directly reflects the JavaScript payload from the `zd_echo` parameter into the HTTP response without proper sanitization.
6.  The server sends the HTTP response containing the attacker's JavaScript payload back to the victim's browser. The Content-Type of the response may not be properly set to prevent script execution.
7.  The victim's browser executes the injected JavaScript code within the context of the Rukovoditel CRM application.
8.  The attacker's JavaScript payload can then perform actions such as stealing cookies, redirecting the user to a phishing site, or modifying the content of the page. This can lead to session hijacking, credential theft, or account takeover.

## Impact

Successful exploitation of this reflected XSS vulnerability can have severe consequences. An attacker can hijack user sessions, potentially gaining unauthorized access to sensitive data within the Rukovoditel CRM system. Credential theft is also possible, allowing the attacker to directly compromise user accounts. Furthermore, the attacker could use the XSS vulnerability to redirect users to phishing sites, tricking them into revealing their login credentials or other personal information. Account takeover could lead to complete control over the CRM data, affecting customer relationships and business operations. While the specific number of victims is unknown, any organization using Rukovoditel CRM version 3.6.4 or earlier is at risk.

## Recommendation

*   Immediately upgrade Rukovoditel CRM to version 3.7 or later to address the vulnerability.
*   Deploy the provided Sigma rule `Detect Rukovoditel CRM XSS Attempt` to monitor for exploitation attempts targeting the `/api/tel/zadarma.php` endpoint.
*   Implement a web application firewall (WAF) rule to filter requests containing potentially malicious JavaScript payloads in the `zd_echo` parameter.
*   Enable proper input validation and output encoding on all user-supplied input fields within the Rukovoditel CRM application, following secure coding practices to prevent future XSS vulnerabilities.
*   Educate users about the risks of clicking on suspicious links and the importance of verifying the authenticity of URLs before visiting them.
