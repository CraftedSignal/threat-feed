---
title: Clerk SSRF Vulnerability in frontendApiProxy Allows Secret Key Leakage
slug: 2026-03-clerk-ssrf
description: A server-side request forgery (SSRF) vulnerability exists in the `clerkFrontendApiProxy` function of the `@clerk/backend` package, allowing an unauthenticated attacker to send the application's `Clerk-Secret-Key` to an attacker-controlled server.
date: "2026-03-28T12:00:00Z"
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

The `clerkFrontendApiProxy` function in `@clerk/backend` versions 3.0.0 through 3.2.2, `@clerk/express` versions 2.0.0 through 2.0.6, `@clerk/hono` versions 0.1.0 through 0.1.4, and `@clerk/fastify` versions 3.1.0 through 3.1.4 is susceptible to a Server-Side Request Forgery (SSRF) vulnerability. This flaw enables an unauthenticated attacker to craft malicious request paths that, when processed by the proxy, result in the application's `Clerk-Secret-Key` being transmitted to a server under the…
