---
title: Auth.js getToken() Vulnerability Leads to Denial of Service
slug: 2026-07-authjs-dos
description: 'A vulnerability in the Auth.js `getToken()` helper function (next-auth and @auth/core) allows unauthenticated attackers to trigger an uncaught exception via a malformed `Authorization: Bearer` header, leading to a per-request denial of service in affected applications.'
date: "2026-07-23T14:45:37Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - web-application
  - javascript
  - input-validation
vendors:
  - Auth.js
products:
  - '@auth/core'
  - next-auth
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: 'Denial of service: an unauthenticated request carrying a malformed Bearer authorization header can raise an unhandled exception in any handler that calls `getToken()`.'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-xmf8-cvqr-rfgj
---

A high-severity vulnerability has been identified in the `getToken()` helper within the `next-auth` and `@auth/core` JavaScript libraries, specifically affecting versions `<= 5.0.0-beta.25` for `next-auth` and `< 0.41.3` for `@auth/core`. This flaw, tracked as CWE-20 (Improper Input Validation), enables an unauthenticated attacker to induce a denial-of-service condition. When an application that directly calls `getToken()` receives a request with a malformed `Authorization: Bearer` header containing invalid percent-encoding, the function attempts to URL-decode the value. This decoding step can trigger an uncaught exception if not explicitly handled by the application, causing the request handler to crash or become unresponsive. This impacts application availability, particularly in API routes, middleware, and server-side request handlers where `getToken()` is commonly employed, though it does not expose sensitive data or bypass authentication.

## Attack Chain

1. An unauthenticated attacker crafts an HTTP request targeting a web application that uses the vulnerable `getToken()` helper.
2. The attacker includes a malformed `Authorization: Bearer` header in the request, where the bearer token portion contains invalid percent-encoding (e.g., `%xx` where `xx` is not a valid hexadecimal character).
3. The web application's API route, middleware, or server-side request handler receives the malicious request and calls the `getToken()` function.
4. The `getToken()` function, in the absence of a session cookie, attempts to URL-decode the malformed bearer value from the `Authorization` header.
5. Due to the invalid percent-encoding, the URL-decoding process fails and throws an uncaught exception within the `getToken()` helper.
6. Unless the application has a specific `try/catch` block surrounding the `getToken()` call, this uncaught exception propagates, leading to the crash or unresponsiveness of the request handler.
7. The application experiences a denial-of-service condition for that specific request, impacting availability.

## Impact

The primary impact of this vulnerability is a denial of service (DoS). An unauthenticated request containing a specially crafted, malformed `Authorization: Bearer` header can cause an unhandled exception in any application handler that invokes the `getToken()` function directly. This results in the affected request failing to complete, rendering the specific endpoint unavailable for that transaction. The impact is isolated to individual requests and primarily affects application availability. It does not lead to the exposure of tokens, session data, or other sensitive information, nor does it bypass existing authentication mechanisms. The vulnerability is categorized under CWE-20: Improper Input Validation.

## Recommendation

* Upgrade `next-auth` to a patched version greater than `5.0.0-beta.31` or `4.24.14` (or `@auth/core` to `0.41.3` or newer) to automatically address the vulnerability.
* If immediate upgrade is not possible, implement a `try/catch` block around all calls to `getToken()` within your application code to handle potential exceptions gracefully and treat them as an invalid token.
* Consider deploying an edge proxy or middleware to strip or normalize incoming `Authorization` headers with malformed percent-encoding before they reach the application.
