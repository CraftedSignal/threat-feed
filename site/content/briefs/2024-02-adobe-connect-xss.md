---
title: Adobe Connect Reflected XSS Vulnerability (CVE-2026-27245)
slug: 2024-02-adobe-connect-xss
description: Adobe Connect versions 2025.3, 12.10, and earlier are vulnerable to a reflected Cross-Site Scripting (XSS) attack, enabling attackers to execute malicious JavaScript in a victim's browser by enticing them to visit a crafted URL.
date: "2026-04-14T18:16:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - adobe-connect
  - cve-2026-27245
  - reflected-xss
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-27245
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27245
  - https://helpx.adobe.com/security/products/connect/apsb26-37.html
iocs:
  - type: email
    value: '[email&#160;protected]'
  - type: url
    value: https://nvd.nist.gov
  - type: url
    value: https://helpx.adobe.com/security/products/connect/apsb26-37.html
ioc_counts:
  email: 1
  url: 2
rules:
  - title: Detect Adobe Connect XSS Attempt via URI
    description: Detects potential reflected XSS attempts targeting Adobe Connect by looking for JavaScript-like syntax in the URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Reflected XSS Payloads in URI
    description: This rule detects generic reflected XSS payloads in web server URIs.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A reflected Cross-Site Scripting (XSS) vulnerability, identified as CVE-2026-27245, affects Adobe Connect versions 2025.3, 12.10, and earlier. This vulnerability allows an attacker to inject malicious JavaScript code into a user's browser by convincing them to click on a specially crafted URL. When the victim visits the malicious URL, the injected script executes within their browser session, potentially enabling the attacker to steal cookies, redirect the user to a malicious website, or deface the web page. This vulnerability poses a significant risk to Adobe Connect users, as it can lead to account compromise and data breaches. Exploitation requires user interaction, but the impact can be severe.

## Attack Chain

1. The attacker crafts a malicious URL containing a JavaScript payload within a parameter.
2. The attacker distributes the crafted URL via email, social media, or other means to a targeted user.
3. The victim clicks on the malicious link, unknowingly initiating the XSS attack.
4. The user's browser sends a request to the Adobe Connect server with the malicious JavaScript in the URL.
5. The Adobe Connect server reflects the malicious JavaScript code back to the user's browser without proper sanitization.
6. The victim's browser executes the reflected JavaScript code within the context of the Adobe Connect application.
7. The attacker can then steal the victim's session cookies.
8. Using the stolen cookies, the attacker can hijack the victim's session, gaining unauthorized access to their Adobe Connect account and data.

## Impact

Successful exploitation of this reflected XSS vulnerability (CVE-2026-27245) in Adobe Connect could lead to unauthorized access to user accounts, sensitive data, and the Adobe Connect environment. An attacker could potentially deface web pages, redirect users to phishing sites, or inject malware. The impact ranges from user-specific data theft to wider compromise of the Adobe Connect platform. While the number of victims is unknown, any organization using the affected Adobe Connect versions is vulnerable.

## Recommendation

*   Upgrade to a patched version of Adobe Connect that addresses CVE-2026-27245. Refer to the vendor advisory at https://helpx.adobe.com/security/products/connect/apsb26-37.html for specific upgrade instructions.
*   Deploy the Sigma rule `Detect Adobe Connect XSS Attempt via URI` to identify requests containing suspicious JavaScript payloads targeting Adobe Connect.
*   Educate users to be cautious about clicking on URLs received from untrusted sources to mitigate the initial access vector.
*   Monitor web server logs for unusual URI patterns and JavaScript-like syntax using the `Detect Reflected XSS Payloads in URI` Sigma rule.
