---
title: i18next-http-middleware HTTP Response Splitting and DoS Vulnerability
slug: 2024-01-i18next-http-middleware-crlf
description: i18next-http-middleware versions before 3.9.3 are vulnerable to HTTP response splitting and denial-of-service attacks due to unsanitized Content-Language headers, potentially leading to session fixation, cache poisoning, reflected XSS, or complete service disruption depending on the Node.js version.
date: "2024-01-03T12:00:00Z"
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

The `i18next-http-middleware` library, in versions prior to 3.9.3, exhibits a vulnerability stemming from insufficient sanitization of user-controlled language values. These values are written into the `Content-Language` HTTP response header. The `utils.escape()` function, employed for sanitization, performs HTML-entity encoding but fails to strip critical characters like carriage return and line feed. When the application uses an older `i18next` (< 19.5.0) or produces raw detected values, CRLF…
