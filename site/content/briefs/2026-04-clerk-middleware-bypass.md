---
title: Clerk JavaScript SDK Middleware Route Protection Bypass
slug: 2026-04-clerk-middleware-bypass
description: A vulnerability in `@clerk/nextjs`, `@clerk/nuxt`, and `@clerk/astro` allows crafted requests to bypass middleware gating via `createRouteMatcher`, potentially exposing protected routes if downstream authentication checks are absent.
date: "2026-04-17T12:00:00Z"
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

A critical vulnerability exists in the `@clerk/nextjs`, `@clerk/nuxt`, and `@clerk/astro` JavaScript SDKs, specifically within the `createRouteMatcher` function. This flaw, reported on April 13, 2026, and patched by April 15, 2026, allows attackers to craft specific HTTP requests that bypass the middleware-based route protection implemented using `createRouteMatcher`. This bypass allows unauthenticated or unauthorized users to access routes intended to be protected by the middleware…
