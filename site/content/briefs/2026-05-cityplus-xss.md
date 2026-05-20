---
title: 'CVE-2026-5783: CityPLus Reflected XSS Vulnerability'
slug: 2026-05-cityplus-xss
description: CVE-2026-5783 is a reflected cross-site scripting (XSS) vulnerability in Beyaz Computer Software Design Industry and Trade Ltd. Co. CityPLus before version V24.29750.1.0, allowing attackers to inject malicious scripts into web pages viewed by users.
date: "2026-05-20T16:17:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cve
  - xss
  - reflected-xss
  - web-application
vendors:
  - Beyaz Computer Software Design Industry and Trade Ltd. Co.
products:
  - CityPLus
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5783
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5783
  - https://siberguvenlik.gov.tr/guvenlik-bildirimleri/detay/tr-26-0263
rules:
  - title: Detect CVE-2026-5783 Exploitation — Suspicious URI Query Parameters
    description: Detects CVE-2026-5783 exploitation — suspicious URI query parameters indicative of reflected XSS attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-5783 Exploitation — Script Tag in URL
    description: Detects CVE-2026-5783 exploitation — looking for script tags directly in the URL.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Beyaz Computer Software Design Industry and Trade Ltd. Co.'s CityPLus software is vulnerable to a reflected cross-site scripting (XSS) vulnerability, identified as CVE-2026-5783. This vulnerability affects CityPLus versions prior to V24.29750.1.0. A remote attacker can exploit this vulnerability by injecting arbitrary web scripts into a CityPLus web page. When a user visits the crafted URL, the injected script executes in the user's browser within the context of the CityPLus website. This can lead to information disclosure, session hijacking, or defacement of the website. Defenders should ensure CityPLus is updated to the latest version to mitigate this risk.

## Attack Chain

1.  The attacker crafts a malicious URL containing a JavaScript payload designed to execute in the context of CityPLus. This payload is often URL-encoded.
2.  The attacker distributes the crafted URL to potential victims, often through phishing emails, social media, or other methods.
3.  A victim clicks on the malicious URL, which directs their web browser to a vulnerable CityPLus endpoint.
4.  The CityPLus application fails to properly sanitize the input provided in the URL, reflecting the malicious JavaScript payload in the server's response.
5.  The victim's web browser receives the HTML response from the server, which includes the unsanitized JavaScript payload.
6.  The victim's browser executes the malicious JavaScript code, believing it to be a legitimate part of the CityPLus website.
7.  The attacker's JavaScript code can perform actions such as stealing cookies, redirecting the user to a malicious website, or modifying the content of the CityPLus page.

## Impact

Successful exploitation of the reflected XSS vulnerability (CVE-2026-5783) in CityPLus could allow an attacker to execute arbitrary JavaScript code in the victim's browser. This could result in session hijacking, where the attacker gains control of the user's CityPLus session. The attacker could also redirect the user to a malicious website, steal sensitive information, or deface the CityPLus website. The severity of the impact depends on the privileges of the compromised user and the sensitive information accessible through the CityPLus application.

## Recommendation

*   Upgrade CityPLus to version V24.29750.1.0 or later to patch CVE-2026-5783.
*   Deploy the Sigma rule "Detect CVE-2026-5783 Exploitation — Suspicious URI Query Parameters" to identify potential exploitation attempts.
*   Educate users about the risks of clicking on suspicious links in emails or on social media to prevent initial access.
