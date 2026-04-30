---
title: Clerk Authorization Bypass Vulnerability
slug: 2026-04-clerk-auth-bypass
description: Clerk has an authorization bypass vulnerability in multiple packages where the `has()` and `auth.protect()` predicates can incorrectly return true, potentially allowing unauthorized actions.
date: "2026-04-30T18:20:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization
  - bypass
  - clerk
  - cve-2026-42349
vendors:
  - Clerk
products:
  - '@clerk/shared'
  - '@clerk/backend'
  - '@clerk/nextjs'
  - '@clerk/clerk-js'
  - '@clerk/clerk-react'
  - '@clerk/react'
  - '@clerk/vue'
  - '@clerk/astro'
  - '@clerk/nuxt'
  - '@clerk/clerk-expo'
  - '@clerk/expo'
  - '@clerk/react-router'
  - '@clerk/tanstack-react-start'
  - '@clerk/chrome-extension'
  - '@clerk/fastify'
  - '@clerk/express'
  - '@clerk/hono'
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-w24r-5266-9c3c
rules:
  - title: Clerk Auth.protect Bypass
    description: Detects calls to auth.protect in Next.js that include unauthenticatedUrl, unauthorizedUrl, or token, which could indicate an attempted bypass.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Clerk Combined Auth Check Bypass
    description: Detects potential exploitation of the combined authorization check bypass by monitoring for unusual process creations following authentication.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical authorization bypass vulnerability has been identified in Clerk's authorization predicates (`has()` and `auth.protect()`) across multiple SDKs, including `@clerk/shared`, `@clerk/nextjs`, and `@clerk/backend`. This flaw, reported on April 18, 2026, and patched on April 22, 2026, can lead to incorrect authorization decisions when combining multiple authorization dimensions (e.g., reverification with role). Specifically, the predicates may return `true` even if the user does not satisfy all required conditions, potentially allowing unauthorized access to gated actions. A secondary bypass exists in `@clerk/nextjs`, where `auth.protect()` silently discards authorization parameters under certain conditions. The vulnerability affects applications using specific combinations of authorization checks, emphasizing the need for immediate patching.

## Attack Chain

1.  An attacker identifies an application utilizing affected Clerk packages and vulnerable authorization checks.
2.  The attacker targets an endpoint protected by a combined authorization check (e.g., requiring a specific role and reverification).
3.  The attacker crafts a request that satisfies one, but not all, of the authorization conditions.
4.  Due to the bypass vulnerability, the `has()` or `auth.protect()` predicate incorrectly returns `true`.
5.  The application grants the attacker access to the protected resource or functionality.
6.  In the case of the `@clerk/nextjs` bypass, the attacker might exploit the silent discarding of authorization parameters when `unauthenticatedUrl`, `unauthorizedUrl`, or `token` are also present in the `auth.protect()` call, effectively bypassing authorization.
7.  The attacker performs unauthorized actions, such as modifying data or accessing restricted areas of the application.

## Impact

Successful exploitation of this vulnerability could lead to unauthorized access to sensitive resources and functionalities within applications using Clerk for authentication and authorization. This could result in data breaches, privilege escalation, and other security incidents. The vulnerability affects a wide range of Clerk packages, potentially impacting a significant number of applications relying on Clerk for access control. Immediate patching is crucial to mitigate the risk of exploitation.

## Recommendation

*   Upgrade to the latest patch release of the consuming app's framework package as specified in the advisory to remediate CVE-2026-42349.
*   If immediate upgrade is not feasible, implement the suggested workaround of splitting combined `has()` or `auth.protect()` calls into sequential single-condition checks as described in the advisory.
*   Deploy the Sigma rule `ClerkAuthProtectBypass` to detect potential exploitation attempts by monitoring for calls to `auth.protect` that include `unauthenticatedUrl`, `unauthorizedUrl`, or `token` parameters.
*   Deploy the Sigma rule `ClerkCombinedAuthCheckBypass` to identify suspicious process creation events that may indicate unauthorized access due to the authorization bypass.
