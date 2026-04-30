---
title: Clerk SSRF Vulnerability in frontendApiProxy Allows Secret Key Leakage
slug: 2026-03-clerk-ssrf
description: A server-side request forgery (SSRF) vulnerability exists in the `clerkFrontendApiProxy` function of the `@clerk/backend` package, allowing an unauthenticated attacker to send the application's `Clerk-Secret-Key` to an attacker-controlled server.
date: "2026-03-28T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - vulnerability
  - clerk
  - cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-gjxx-92w9-8v8f
rules:
  - title: Detect Requests with Double Slashes to Clerk Proxy Endpoint
    description: Detects HTTP requests with double slashes in the path targeting the Clerk proxy endpoint, potentially indicating an SSRF exploitation attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Requests with Double Slashes to Clerk Proxy Endpoint (Windows)
    description: Detects HTTP requests with double slashes in the path targeting the Clerk proxy endpoint, potentially indicating an SSRF exploitation attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - windows
rules_count: 2
---

The `clerkFrontendApiProxy` function in `@clerk/backend` versions 3.0.0 through 3.2.2, `@clerk/express` versions 2.0.0 through 2.0.6, `@clerk/hono` versions 0.1.0 through 0.1.4, and `@clerk/fastify` versions 3.1.0 through 3.1.4 is susceptible to a Server-Side Request Forgery (SSRF) vulnerability. This flaw enables an unauthenticated attacker to craft malicious request paths that, when processed by the proxy, result in the application's `Clerk-Secret-Key` being transmitted to a server under the attacker's control. Only applications that have explicitly enabled the `frontendApiProxy` feature are affected. This feature is not enabled by default, limiting the scope of potential impact. Notably, `@clerk/nextjs` users are not affected due to the framework's handling of repeated slashes in request paths, which mitigates the vulnerability.

## Attack Chain

1. An attacker identifies an application that has the `frontendApiProxy` feature enabled and is running a vulnerable version of `@clerk/backend`, `@clerk/express`, `@clerk/hono`, or `@clerk/fastify`.
2. The attacker crafts a malicious HTTP request targeting the proxy endpoint (`/__clerk/` by default). The request path includes double slashes or other path manipulation techniques to bypass intended routing logic.
3. The vulnerable `clerkFrontendApiProxy` function processes the crafted request without proper sanitization or validation of the request path.
4. Due to the SSRF vulnerability, the proxy makes an internal request to an unintended destination, potentially including an attacker-controlled server.
5. The application's `Clerk-Secret-Key` is inadvertently included in the headers or body of the internal request made by the proxy.
6. The attacker-controlled server receives the request containing the `Clerk-Secret-Key`.
7. The attacker extracts the `Clerk-Secret-Key` from the captured request.
8. With the compromised `Clerk-Secret-Key`, the attacker can impersonate the application, access protected resources, or perform other unauthorized actions within the Clerk ecosystem.

## Impact

Successful exploitation of this SSRF vulnerability allows an attacker to obtain the `Clerk-Secret-Key` of a vulnerable application. While internal logs from Clerk show no evidence of active exploitation, the potential impact of a compromised secret key is significant. An attacker with the key can impersonate the application, potentially leading to unauthorized access to user data, modification of application settings, or other malicious activities. The severity is further heightened because a successful attack can occur without authentication.

## Recommendation

*   Upgrade to the patched version of `@clerk/backend` (3.2.3), `@clerk/express` (2.0.7), `@clerk/hono` (0.1.5), or `@clerk/fastify` (3.1.5) immediately if you are using the `frontendApiProxy` feature.
*   Rotate your Clerk Secret Key in the [Clerk Dashboard](https://dashboard.clerk.com) under **API Keys** after upgrading to mitigate potential compromise, as recommended by the advisory.
*   Audit access logs for requests to your proxy endpoint (`/__clerk/` by default) containing double slashes in the path to detect potential exploitation attempts.
*   Deploy the Sigma rule provided below to identify requests with double slashes to the Clerk proxy endpoint.
