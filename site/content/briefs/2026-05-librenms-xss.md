---
title: LibreNMS Multiple XSS Vulnerabilities
slug: 2026-05-librenms-xss
description: Multiple reflected cross-site scripting (XSS) vulnerabilities exist in LibreNMS versions 25.12.0 to before 26.3.0, allowing an attacker to inject malicious code into a user's browser session.
date: "2026-05-12T14:10:57Z"
type: threat
types:
  - threat
severities:
  - medium
tags:
  - librenms
  - xss
  - reflected-xss
vendors:
  - LibreNMS
products:
  - LibreNMS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0562/
  - https://github.com/librenms/librenms/security/advisories/GHSA-5gm9-622f-qcg5
rules:
  - title: Detect LibreNMS XSS Attempt via GET Request
    description: Detects potential XSS attempts against LibreNMS by identifying GET requests with common XSS payloads in the URI.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect LibreNMS XSS Attempt via POST Request
    description: Detects potential XSS attempts against LibreNMS by identifying POST requests with common XSS payloads in the request body.
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

Multiple reflected cross-site scripting (XSS) vulnerabilities were discovered in LibreNMS, a network monitoring system. These vulnerabilities affect LibreNMS versions equal to or after 25.12.0 and before 26.3.0. An attacker can exploit these vulnerabilities by injecting arbitrary web scripts into a user's browser. This is achieved by crafting malicious URLs or manipulating HTTP requests that, when processed by the application, include the attacker's payload in the generated web page. When a user clicks on the malicious link or otherwise interacts with the crafted request, the injected script executes in their browser within the context of the LibreNMS application, potentially leading to session hijacking, defacement, or sensitive information theft.

## Attack Chain

1.  Attacker identifies an endpoint within the LibreNMS application vulnerable to XSS. This could be a page that reflects user input in the URL or POST data without proper sanitization.
2.  The attacker crafts a malicious URL containing a JavaScript payload designed to execute arbitrary code in the victim's browser. This payload could be designed to steal cookies, redirect the user, or deface the application.
3.  The attacker distributes the malicious URL to potential victims through phishing emails, social media, or other means.
4.  A user clicks on the malicious URL. The request is sent to the LibreNMS server.
5.  The LibreNMS server processes the request and includes the malicious JavaScript payload in the generated HTML response.
6.  The user's browser renders the HTML page, executing the injected JavaScript code.
7.  The injected script performs malicious actions, such as stealing the user's session cookie or redirecting the user to a fake login page.
8.  The attacker uses the stolen cookie to hijack the user's session and gain unauthorized access to the LibreNMS application, potentially allowing them to modify configurations, access sensitive data, or perform other administrative tasks.

## Impact

Successful exploitation of these XSS vulnerabilities can lead to account compromise, sensitive information disclosure, and potential defacement of the LibreNMS interface. While the exact number of affected installations is unknown, LibreNMS is used by a variety of organizations for network monitoring, including enterprises and educational institutions. A successful attack could grant unauthorized access to network monitoring data, potentially revealing sensitive information about the targeted organization's infrastructure.

## Recommendation

*   Upgrade LibreNMS to version 26.3.0 or later to remediate the XSS vulnerabilities as recommended in the LibreNMS security advisory [https://github.com/librenms/librenms/security/advisories/GHSA-5gm9-622f-qcg5](https://github.com/librenms/librenms/security/advisories/GHSA-5gm9-622f-qcg5).
*   Deploy the Sigma rule to detect potential XSS attempts against LibreNMS by monitoring for suspicious patterns in HTTP requests.
*   Implement a web application firewall (WAF) to filter out malicious requests and prevent XSS attacks.
