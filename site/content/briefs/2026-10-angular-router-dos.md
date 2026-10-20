---
brief_id: brief-2026-10-20-angular-router-dos
event_id: brief-2026-10-20-angular-router-dos
revision: 1
activity_at: "2026-10-20T23:56:07Z"
title: 'Angular: Denial of service via RouterLink query parameter retention (CVE-2026-111751)'
slug: 2026-10-angular-router-dos
description: A memory exhaustion vulnerability in @angular/router during server-side rendering allows remote, unauthenticated attackers to crash Node.js SSR workers by sending concurrent requests with dense, oversized query strings.
date: "2026-10-20T23:56:07Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source documentation is sufficient for immediate action.
cpes:
  - cpe:2.3:a:google:angular:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - angular
  - nodejs
  - ssr
vendors:
  - Google
products:
  - Angular (@angular/router >= 22.0.0 < 22.2.1)
  - Angular (@angular/router >= 21.2.0 < 21.2.25)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Successful exploitation allows an unauthenticated remote attacker to exhaust the Node.js old-space heap with modest concurrent request volume, terminating the SSR worker with an unrecoverable JavaScript heap out of memory fatal crash.
    confidence_band: high
cves:
  - id: CVE-2026-111751
    kev_status: unknown
references:
  - https://github.com/advisories/GHSA-57xq-rjx2-v5xh
  - https://github.com/angular/angular/pull/66181
  - https://github.com/angular/angular/pull/70953
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Web Engineering
  immediate_actions:
    - action: Upgrade @angular/router to 22.2.1 or 21.2.25
      owner: Web Engineering
      due: 24h
      evidence: Source documentation identifies these versions as patched.
  mitigation_plan:
    - priority: immediate
      action: Configure edge proxy to reject long query strings (> 2KB)
      owner: IT Operations
      addresses: CVE-2026-111751
      evidence: Source workaround recommends limiting query string length at the edge.
---

A denial of service (DoS) vulnerability exists in `@angular/router` when Server-Side Rendering (SSR) is enabled on Node.js (V8) and `RouterLink` directives use `queryParamsHandling` set to `'merge'` or `'preserve'`. Introduced in version 21.2.0, a refactor to signals caused the `RouterLink` directive to persistently cache `UrlTree` instances in the heap for the duration of the request. 

In applications using `'merge'` or `'preserve'` configurations, every rendered link copies incoming request query parameters into its own `UrlTree`. Because SSR maintains active `RouterLink` instances while awaiting asynchronous data or page rendering, an attacker can supply large, dense query parameter payloads to force multiplicative heap consumption. This amplification causes the Node.js old-space heap to reach its limit, triggering a fatal out-of-memory crash. The vulnerability affects `@angular/router` versions 21.2.0 through 21.2.24 and 22.0.0 through 22.2.0.

## Attack Chain

1. Attacker identifies a public-facing Angular application utilizing Server-Side Rendering (SSR).
2. Attacker confirms the application supports `queryParamsHandling` logic (e.g., merging/preserving parameters into navigation links).
3. Attacker crafts multiple concurrent HTTP requests containing large query strings with high-density parameters (e.g., thousands of numeric keys).
4. Node.js SSR worker receives concurrent requests, initiating the Angular rendering lifecycle for each.
5. The `RouterLink` directive's refactored signal caching logic pins individual `UrlTree` objects containing the attacker's bloated query maps to the heap.
6. Memory usage grows multiplicatively per request as the SSR worker processes route dependencies and waits for async operations.
7. Node.js old-space heap capacity is exhausted, causing the SSR worker process to terminate due to an unrecoverable "out of memory" fatal error.

## Impact

Successful exploitation results in service unavailability for the targeted SSR application. By saturating the heap with concurrent requests, an attacker can force continuous restarts or process termination of the Node.js runtime, effectively denying service to legitimate users. The impact is significant for high-traffic environments where SSR is a core component of the user experience. Pure client-side Angular applications (SPAs) are unaffected as the memory pressure remains confined to individual client browsers rather than the server-side process.

## Recommendation

1. Upgrade `@angular/router` to version `22.2.1` or `21.2.25` immediately to address the memory retention issue documented in CVE-2026-111751.
2. If an immediate upgrade is not feasible, configure edge infrastructure (e.g., Nginx, WAF, or AWS ALB) to reject incoming HTTP requests with query strings exceeding 2,048 bytes to mitigate the amplification factor.
3. Implement a server-side middleware check to validate the length of `req.url` before passing the request to the Angular SSR handler.
4. Audit application route configurations to remove global `defaultQueryParamsHandling: 'merge'` or `'preserve'` settings; explicitly specify only necessary parameters on `RouterLink` elements to minimize heap exposure.
5. Increase the `--max-old-space-size` Node.js flag as a short-term buffer, though note this does not provide complete protection against sustained, high-volume exploitation attempts.
