---
title: i18next-http-middleware HTTP Response Splitting and DoS Vulnerability
slug: 2024-01-i18next-http-middleware-crlf
description: i18next-http-middleware versions before 3.9.3 are vulnerable to HTTP response splitting and denial-of-service attacks due to unsanitized Content-Language headers, potentially leading to session fixation, cache poisoning, reflected XSS, or complete service disruption depending on the Node.js version.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - crlf-injection
  - http-response-splitting
  - denial-of-service
  - i18next
vendors:
  - npm
products:
  - i18next-http-middleware
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-c3h8-g69v-pjrg
rules:
  - title: Detect i18next-http-middleware CRLF Injection Attempt
    description: Detects attempts to exploit CRLF injection vulnerability in i18next-http-middleware by identifying URL-encoded newline characters (%0d, %0a) in the request URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect i18next-http-middleware DoS - ERR_INVALID_CHAR
    description: Detects potential DoS attacks against Node.js applications using i18next-http-middleware by identifying ERR_INVALID_CHAR errors in server logs, indicative of CRLF injection attempts.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The `i18next-http-middleware` library, in versions prior to 3.9.3, exhibits a vulnerability stemming from insufficient sanitization of user-controlled language values. These values are written into the `Content-Language` HTTP response header. The `utils.escape()` function, employed for sanitization, performs HTML-entity encoding but fails to strip critical characters like carriage return and line feed. When the application uses an older `i18next` (< 19.5.0) or produces raw detected values, CRLF sequences within the `lng` parameter reach `res.setHeader('Content-Language', ...)` without proper escaping. This flaw can result in HTTP response splitting (Node.js < 14.6.0) or a denial-of-service condition (Node.js >= 14.6.0), impacting all concurrent users of the affected process.  The same vulnerability is triggered multiple times per request. This issue is resolved in version 3.9.3.

## Attack Chain

1.  The attacker crafts a malicious HTTP request targeting an application using a vulnerable version of `i18next-http-middleware`. The request includes a `lng` parameter with a payload containing CRLF sequences (e.g., `%0d%0a`).
2.  The `i18next-http-middleware` receives the request and extracts the language value from the `lng` parameter.
3.  The extracted language value is passed through `utils.escape()`, which performs HTML-entity encoding but does not remove CRLF sequences.
4.  The middleware attempts to set the `Content-Language` header using `res.setHeader()`, incorporating the unsanitized language value.
5.  If the Node.js version is less than 14.6.0, the `res.setHeader()` function processes the CRLF sequences, resulting in HTTP response splitting. This allows the attacker to inject arbitrary headers and control parts of the response body.
6.  If the Node.js version is 14.6.0 or greater, `res.setHeader()` throws an `ERR_INVALID_CHAR` error because the value contains CRLF sequences.
7.  The middleware fails to catch this error, and the exception propagates, leading to an unhandled exception.
8.  The unhandled exception causes the Node.js process to terminate or become unresponsive, resulting in a denial-of-service condition for all concurrent users sharing that process.

## Impact

Successful exploitation allows attackers to inject arbitrary HTTP headers, leading to session fixation, cache poisoning, or reflected XSS attacks. In Node.js versions 14.6.0 and later, exploitation leads to a denial-of-service condition, potentially impacting all users of an application instance. This can result in significant disruption of service availability and potential data compromise. The number of affected applications is unknown, but any application using a vulnerable version of `i18next-http-middleware` is at risk.

## Recommendation

*   Upgrade `i18next-http-middleware` to version 3.9.3 or later to address the vulnerability by patching the `utils.sanitizeHeaderValue()` function, as described in the advisory.
*   Deploy the Sigma rule `Detect i18next-http-middleware CRLF Injection Attempt` to monitor for exploitation attempts by detecting suspicious URL-encoded characters in HTTP requests.
*   Implement a Web Application Firewall (WAF) rule to reject requests containing `\r` or `\n` characters in query parameters, cookies, and path segments as a partial mitigation, as suggested in the advisory.
*   Enable web server logging to ensure events related to potential exploits are captured for analysis.
