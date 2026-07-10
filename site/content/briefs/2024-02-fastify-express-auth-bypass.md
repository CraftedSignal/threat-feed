---
title: '@fastify/express Authentication Bypass via URL Normalization Gaps'
slug: 2024-02-fastify-express-auth-bypass
description: A vulnerability exists in `@fastify/express` v4.0.4 that allows complete bypass of path-scoped authentication middleware via URL normalization gaps, specifically through duplicate slashes and semicolon delimiters, leading to unauthorized access to protected routes.
date: "2024-02-29T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - fastify
  - express
  - authentication-bypass
  - url-normalization
  - cve-2026-33808
vendors:
  - Fastify
products:
  - '@fastify/express'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-22037
    cvss: 8.4
    epss: 0.00084
references:
  - https://github.com/advisories/GHSA-6hw5-45gm-fj88
rules:
  - title: Detect Fastify Express Double Slash Authentication Bypass
    description: Detects attempts to bypass authentication in Fastify/Express applications by using double slashes in URLs.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Fastify Express Semicolon Authentication Bypass
    description: Detects attempts to bypass authentication in Fastify/Express applications by using semicolons in URLs.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability exists in `@fastify/express` version 4.0.4 related to URL normalization. When Fastify router normalization options (`ignoreDuplicateSlashes` or `useSemicolonDelimiter`) are enabled, the `@fastify/express` module fails to properly normalize URLs before passing them to Express middleware. This discrepancy allows attackers to bypass authentication and authorization checks implemented in Express middleware. The vulnerability stems from the `enhanceRequest` function in `index.js`, which doesn't normalize duplicate slashes or strip semicolon-delimited parameters, leading to a mismatch between Fastify's route matching and Express's middleware handling. This issue is distinct from CVE-2026-22037, which addressed percent-encoding bypass. Successful exploitation grants unauthenticated access to protected resources, impacting applications that rely on Express middleware for security.

## Attack Chain

1. An attacker identifies a protected route, such as `/admin/dashboard`, that is secured by Express middleware within a Fastify application using `@fastify/express`.
2. The attacker crafts a malicious URL containing either duplicate slashes (e.g., `//admin/dashboard`) or semicolon delimiters (e.g., `/admin;bypass`).
3. The attacker sends an HTTP request to the target server using the crafted malicious URL.
4. Fastify's router, configured with `ignoreDuplicateSlashes: true` or `useSemicolonDelimiter: true`, normalizes the URL for route matching.
5. `@fastify/express`'s `enhanceRequest` function passes the original, un-normalized URL to the Express middleware.
6. The Express middleware, expecting the normalized URL (e.g., `/admin/dashboard`), fails to match the malicious URL (e.g., `//admin/dashboard` or `/admin;bypass`).
7. The authentication/authorization checks in the Express middleware are bypassed.
8. The Fastify route handler executes, granting the attacker unauthorized access to the protected resource, potentially leading to data breaches or other malicious activities.

## Impact

This vulnerability allows for complete authentication bypass in applications that utilize Express middleware for path-based access control and are built on `@fastify/express`. Successful exploitation leads to unauthorized access to protected resources like admin panels, APIs, and sensitive user data. The duplicate slash vector impacts applications with `ignoreDuplicateSlashes: true`, while the semicolon vector affects those with `useSemicolonDelimiter: true`. This bypass affects all Express middleware using prefix path matching, including popular authentication, authorization, and rate-limiting packages. The root cause lies in the unexpected behavior of `@fastify/express` and its interaction with Fastify's router options, potentially affecting a large number of applications.

## Recommendation

- Deploy the Sigma rule `Detect Fastify Express Double Slash Authentication Bypass` to detect attempts to exploit the duplicate slash vulnerability via web server logs.
- Deploy the Sigma rule `Detect Fastify Express Semicolon Authentication Bypass` to detect attempts to exploit the semicolon delimiter vulnerability via web server logs.
- Upgrade to a patched version of `@fastify/express` when available. This should include URL normalization before passing to Express middleware as suggested in the advisory.
- Review Fastify configurations to understand if `ignoreDuplicateSlashes: true` or `useSemicolonDelimiter: true` are actively used and assess the impact of disabling them until a patch is applied.
