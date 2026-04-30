---
title: Clerk JavaScript SDK Middleware Route Protection Bypass
slug: 2026-04-clerk-middleware-bypass
description: A vulnerability in `@clerk/nextjs`, `@clerk/nuxt`, and `@clerk/astro` allows crafted requests to bypass middleware gating via `createRouteMatcher`, potentially exposing protected routes if downstream authentication checks are absent.
date: "2026-04-17T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - route-bypass
  - middleware-vulnerability
  - javascript-sdk
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-vqx2-fgx2-5wq9
rules:
  - title: Detect Clerk Middleware Bypass Attempt
    description: Detects attempts to bypass Clerk middleware by identifying unusual HTTP requests potentially crafted to exploit the `createRouteMatcher` vulnerability.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Clerk Auth Bypass - HTTP 403 Missing
    description: Detects requests to protected paths without a preceding 403 Forbidden, indicating a potential bypass of the authentication middleware.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Clerk Auth Bypass - Suspicious User-Agent
    description: Detects requests to protected paths using suspicious User-Agent strings, indicating a potential bypass of the authentication middleware.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 3
---

A critical vulnerability exists in the `@clerk/nextjs`, `@clerk/nuxt`, and `@clerk/astro` JavaScript SDKs, specifically within the `createRouteMatcher` function. This flaw, reported on April 13, 2026, and patched by April 15, 2026, allows attackers to craft specific HTTP requests that bypass the middleware-based route protection implemented using `createRouteMatcher`. This bypass allows unauthenticated or unauthorized users to access routes intended to be protected by the middleware, potentially leading to information disclosure or unauthorized actions if proper authentication checks are not implemented further down the application stack. The vulnerability affects applications using versions prior to the patched versions listed below.

## Attack Chain

1. An attacker identifies an application using a vulnerable version of `@clerk/nextjs`, `@clerk/nuxt`, or `@clerk/astro` with middleware route protection implemented using `createRouteMatcher`.
2. The attacker crafts a malicious HTTP request designed to exploit the vulnerability in `createRouteMatcher`, effectively bypassing the intended route matching logic.
3. The crafted request is sent to the application, targeting a route protected by the vulnerable middleware.
4. Due to the bypass, the request proceeds past the middleware gate, reaching the downstream route handler (API route, server component, etc.).
5. If the downstream route handler lacks sufficient authentication or authorization checks, the attacker gains unauthorized access.
6. The attacker performs actions within the application based on the bypassed route, such as accessing sensitive data or triggering unintended functionality.
7. The attacker may then attempt further exploitation or lateral movement within the application.

## Impact

This vulnerability allows attackers to bypass intended route protections. The impact is highly dependent on the application's design. If applications solely rely on `createRouteMatcher` for route protection and lack additional authentication checks in route handlers or server components, the consequences could be severe, including unauthorized access to sensitive data or functionality. While the vulnerability does not compromise existing sessions or allow for user impersonation, it weakens the overall security posture. It is important to note that external APIs which authenticate each request with a token are unaffected on those endpoints, since token verification runs independently.

## Recommendation

*   Immediately upgrade to the patched versions of `@clerk/nextjs`, `@clerk/nuxt`, `@clerk/astro`, and `@clerk/shared` as outlined in the advisory to remediate the vulnerability.
*   Review all route handlers, server components, and server actions protected by `createRouteMatcher` to ensure they include server-side auth checks using `auth()` as a defense-in-depth measure.
*   Deploy the Sigma rule to detect potential exploitation attempts targeting the vulnerable `createRouteMatcher` function in your web server logs.
*   Monitor your application logs for unusual or unauthorized access attempts to protected routes, especially those matching the route patterns configured in `createRouteMatcher`.
*   Run `npm why @clerk/shared` (or your package manager's equivalent) to check the installed version of `@clerk/shared`.
