---
title: Icinga Web Reflected XSS Vulnerability via Malformed Search Requests
slug: 2024-01-icinga-web-xss
description: A reflected cross-site scripting (XSS) vulnerability exists in Icinga Web versions 0.13.0 and earlier, allowing attackers to inject malicious JavaScript into a victim's browser through malformed search requests, potentially leading to arbitrary code execution within the Icinga Web context.
date: "2024-01-24T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - xss
  - web-application
  - icinga
vendors:
  - Icinga
products:
  - Icinga Web
  - icinga-php-library
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1055
    technique_name: Process Injection
references:
  - https://github.com/advisories/GHSA-55wf-5m3q-6jjf
rules:
  - title: Detect Icinga Web XSS Attempt via URI
    description: Detects potential reflected XSS attempts against Icinga Web by monitoring for specific URI patterns indicative of malicious payload injection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1055
    data_sources:
      - webserver
      - linux
  - title: Detect Icinga Web XSS Attempt via cs-uri
    description: Detects potential reflected XSS attempts against Icinga Web by monitoring for specific URI patterns indicative of malicious payload injection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1055
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A reflected XSS vulnerability has been identified in Icinga Web, affecting versions up to 0.13.0. This vulnerability arises from the improper handling of malformed search requests, allowing an attacker to inject arbitrary JavaScript code into a victim's browser. The attacker crafts a malicious URL containing the XSS payload and entices the victim to visit this URL. Upon visiting the crafted URL, the injected JavaScript code executes within the context of the Icinga Web application, potentially enabling the attacker to perform actions on behalf of the victim, steal sensitive information, or compromise the integrity of the application. The vulnerability was patched in version 0.13.1 and will be published as part of `icinga-php-library` version 0.19.2. Icinga Web versions 2.12.0 and later can mitigate the issue by enabling Content-Security-Policy (CSP).

## Attack Chain

1.  The attacker crafts a malicious URL containing a reflected XSS payload within a malformed search request. The payload is designed to execute arbitrary JavaScript code in the victim's browser.
2.  The attacker distributes the crafted URL to potential victims through various means, such as phishing emails, social engineering, or malicious websites.
3.  The victim clicks on the malicious URL, unknowingly initiating the XSS attack.
4.  The victim's browser sends the crafted HTTP request to the Icinga Web server.
5.  The Icinga Web server processes the request and reflects the malicious XSS payload back to the victim's browser in the HTTP response.
6.  The victim's browser renders the HTTP response, executing the injected JavaScript code within the context of the Icinga Web application.
7.  The attacker can now execute arbitrary code, potentially stealing session cookies, performing actions on behalf of the user, or defacing the Icinga Web interface.
8.  The attacker leverages the compromised Icinga Web session to gain unauthorized access to sensitive data or perform malicious activities within the Icinga environment.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary JavaScript code in the context of the Icinga Web application. This can lead to session hijacking, unauthorized access to sensitive data, defacement of the Icinga Web interface, or further compromise of the Icinga infrastructure. While the exact number of victims is unknown, any organization using vulnerable versions of Icinga Web is at risk. The severity is high due to the potential for significant impact on confidentiality, integrity, and availability.

## Recommendation

*   Upgrade Icinga Web to version 0.13.1 or later to patch the vulnerability. This version contains the fix for CVE-2026-42224.
*   For Icinga Web versions 2.12.0 and later, enable Content-Security-Policy (CSP) in the general configuration to mitigate the risk of XSS attacks.
*   Deploy the Sigma rule "Detect Icinga Web XSS Attempt via URI" to your SIEM to detect potential exploitation attempts by monitoring for suspicious URI patterns.
*   Review web server logs for unusual or malformed requests targeting the Icinga Web application to identify potential XSS attack attempts (webserver log source).
