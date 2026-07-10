---
title: Fastify/Express Middleware Path Doubling Authentication Bypass
slug: 2024-01-09-fastify-express-auth-bypass
description: A path handling bug in `@fastify/express` v4.0.4 `onRegister` function causes middleware paths to be doubled when inherited by child plugins, resulting in complete bypass of Express middleware security controls for all routes defined within child plugin scopes that share a prefix with parent-scoped middleware.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - fastify
  - express
  - authentication-bypass
  - middleware
  - path-traversal
vendors:
  - Fastify
products:
  - '@fastify/express'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-hrwm-hgmj-7p9c
rules:
  - title: Detect Fastify Express Middleware Bypass
    description: Detects requests to routes that should be protected by Express middleware but are bypassing it due to the path doubling vulnerability in @fastify/express.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Fastify Child Route Bypassing Auth Middleware
    description: Detects requests to child routes that should have been protected by Express middleware but are not, possibly due to the path doubling vulnerability in @fastify/express.
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

A path handling bug in the `@fastify/express` package allows attackers to bypass authentication in Fastify applications using Express middleware. The vulnerability exists in version 4.0.4 of `@fastify/express`. The `onRegister` function incorrectly handles middleware paths when child plugins are registered with a prefix, causing the middleware paths to be doubled. This leads to a situation where security controls, such as authentication checks, are silently skipped for routes defined within those child plugin scopes. This vulnerability impacts applications using path-scoped middleware and child plugins with matching prefixes, and it affects default Fastify configurations. The issue was reported on April 16, 2026.

## Attack Chain

1.  The application registers Express middleware with a path scope (e.g., `/admin`) using `app.use('/admin', authFn)`. The path is stored as `/admin`.
2.  A child plugin is registered with a prefix that overlaps the middleware path (e.g., `{ prefix: '/admin' }`). This triggers the `onRegister` hook.
3.  The `onRegister` function copies the parent middleware and attempts to re-register it using `instance.use('/admin', authFn)` on the child plugin instance.
4.  The child's `use()` function prepends the plugin prefix to the middleware path, resulting in a doubled path (e.g., `/admin/admin`).
5.  Routes are defined within the child plugin scope using the child's Express instance.
6.  When a request is made to a route within the child scope (e.g., `/admin/secret`), the middleware registered with the doubled path (`/admin/admin`) is not triggered.
7.  Authentication and authorization checks are bypassed because the middleware is not executed for requests to the intended routes.
8.  The attacker gains unauthorized access to resources and data within the child plugin scope.

## Impact

The vulnerability allows for a complete bypass of Express middleware security controls for routes defined within child plugin scopes. This includes authentication, authorization, rate limiting, and other security measures.  The silent nature of the bypass, with no errors or warnings, makes it particularly dangerous.  Successful exploitation could lead to unauthorized access to sensitive data, privilege escalation, and other security breaches. Any child plugin scope that shares a prefix with middleware is affected.

## Recommendation

*   Upgrade to a patched version of `@fastify/express` when available.
*   As a temporary workaround, avoid using child plugins with prefixes that overlap with middleware path scopes until a patch is released.
*   Review existing `@fastify/express` configurations for overlapping middleware paths and child plugin prefixes, and refactor the application to avoid this pattern.
*   Deploy the Sigma rule `Detect Fastify Express Middleware Bypass` to identify potential exploitation attempts by monitoring for requests to routes that should be protected by middleware but are not.
*   Consider implementing additional security measures, such as request validation and input sanitization, to mitigate the risk of unauthorized access.
