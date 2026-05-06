---
title: FlightPHP HTTP Method Override Vulnerability Leads to CSRF and Middleware Bypass
slug: 2024-01-26-flightphp-http-override
description: A vulnerability in FlightPHP core versions before 3.18.1 allows attackers to override HTTP methods via the `X-HTTP-Method-Override` header or `_method` parameter, leading to CSRF escalation, middleware bypass, and cache poisoning.
date: "2024-01-26T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - csrf
  - middleware-bypass
  - cache-poisoning
  - http-method-override
vendors:
  - composer
products:
  - flightphp/core (< 3.18.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-vxrr-w42w-w76g
rules:
  - title: Detect FlightPHP HTTP Method Override via _method Parameter
    description: Detects HTTP requests with the `_method` parameter set to an unsafe HTTP method, indicative of a potential HTTP method override attack in FlightPHP.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect FlightPHP HTTP Method Override via X-HTTP-Method-Override Header
    description: Detects HTTP requests with the `X-HTTP-Method-Override` header set to an unsafe HTTP method, indicating a potential HTTP method override attack in FlightPHP.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

FlightPHP versions prior to 3.18.1 are vulnerable to HTTP method override. The vulnerability resides in the `Request::getMethod()` function within `flight/net/Request.php`. The application unconditionally honors the `X-HTTP-Method-Override` header and the `$_REQUEST['_method']` parameter, even on safe HTTP verbs like GET. This behavior allows an attacker to modify the intended HTTP method, potentially leading to Cross-Site Request Forgery (CSRF) escalation, bypassing of authentication and rate-limiting middleware, and CDN cache poisoning. This vulnerability was discovered by @Rootingg and patched in version 3.18.1 (commit b8dd23a) by introducing the `flight.allow_method_override` setting. Disabling this setting mitigates the vulnerability by ignoring method overrides.

## Attack Chain

1.  The attacker identifies a FlightPHP application using a version prior to 3.18.1.
2.  The attacker locates an endpoint that performs a sensitive action using an unsafe HTTP method (e.g., DELETE, PUT).
3.  The attacker crafts a malicious URL targeting the vulnerable endpoint, using a GET request with either the `_method` parameter (e.g., `/?_method=DELETE`) or the `X-HTTP-Method-Override` header.
4.  For CSRF, the attacker embeds the malicious URL within an HTML `<img>` tag on a website they control.
5.  A victim visits the attacker's website, and their browser automatically sends a GET request to the vulnerable application.
6.  The FlightPHP application incorrectly interprets the GET request as the specified unsafe method (e.g., DELETE) due to the `_method` parameter or `X-HTTP-Method-Override` header.
7.  The application executes the sensitive action (e.g., deleting a resource) on behalf of the victim without proper authorization.
8.  Alternatively, if middleware checks HTTP method to apply controls, this can be bypassed by issuing a GET request with a forged `_method` parameter or `X-HTTP-Method-Override` header.

## Impact

Successful exploitation of this vulnerability can have several significant impacts. It allows attackers to perform CSRF attacks, potentially leading to unauthorized data modification or deletion. Attackers can bypass security middleware that relies on HTTP method verification, gaining unauthorized access to protected resources. The vulnerability also enables CDN cache poisoning, where the CDN caches the response of a GET request that was actually processed as a DELETE or PUT, serving incorrect content to future users. The exact number of affected FlightPHP applications is unknown, but any application using a vulnerable version is potentially at risk.

## Recommendation

*   Upgrade FlightPHP to version 3.18.1 or later to patch CVE-2026-42551.
*   Set the `flight.allow_method_override` setting to `false` to disable HTTP method overriding as described in the advisory.
*   Deploy the Sigma rule `Detect FlightPHP HTTP Method Override via _method Parameter` to detect exploitation attempts using the `_method` parameter.
*   Deploy the Sigma rule `Detect FlightPHP HTTP Method Override via X-HTTP-Method-Override Header` to detect exploitation attempts using the `X-HTTP-Method-Override` header.
