---
title: Denial of Service in Angular Router via Numeric URL Matrix Parameters
slug: 2026-09-angular-ssr-dos
description: A high-severity denial of service vulnerability in @angular/router enables memory exhaustion in Node.js SSR environments through crafted URLs with numeric matrix parameters that trigger oversized V8 object allocation.
date: "2026-09-30T16:26:49Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:google:angular:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - angular
  - nodejs
  - v8
  - cve-2026-101896
vendors:
  - Google
products:
  - '@angular/router (>= 22.0.0, < 22.2.0)'
  - '@angular/router (>= 21.0.0, < 21.2.24)'
  - '@angular/router (>= 20.0.0, < 20.3.32)'
  - '@angular/router (<= 19.2.25)'
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Successful exploitation allows an unauthenticated remote attacker to exhaust the Node.js old-space heap with modest request volume, terminating the SSR worker.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-ff3f-86qr-9cv3
rules:
  - title: Detect Potential SSR DoS Attempt via URL Matrix Parameters
    description: Detects HTTP requests containing semicolons in the URL path, which is a required condition for CVE-2026-101896 exploitation
    platform: sigma
    severity: medium
    tactics:
      - impact
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Block semicolon-containing URLs at the perimeter reverse proxy for Angular-based SSR applications
      owner: IT Operations
      due: 24h
      evidence: Source workaround recommendation
  mitigation_plan:
    - priority: immediate
      action: Upgrade @angular/router to version 22.2.0, 21.2.24, or 20.3.32
      owner: Application Security
      addresses: CVE-2026-101896
      evidence: Source patch information
---

A memory-exhaustion vulnerability (CVE-2026-101896) exists in `@angular/router` when Server-Side Rendering (SSR) is utilized within a Node.js/V8 environment. The vulnerability arises from how the router parses URL segments and matrix parameters into JavaScript objects. When these parameters contain numeric strings, the V8 engine interprets them as array indices rather than object keys. Due to V8's internal property-storage heuristics, these numeric keys cause the allocation of dense array backing stores instead of sparse dictionary storage.

By crafting URLs with repeated numeric matrix parameters (e.g., `/a;990;2522`), an attacker achieves a memory amplification factor of approximately 350x. This allows an unauthenticated remote attacker to trigger a fatal `JavaScript heap out of memory` error in the SSR worker with relatively low concurrency. This vulnerability is specific to SSR implementations and does not affect pure client-side Single Page Applications (SPAs).

## Attack Chain

1. Attacker identifies a target application utilizing Angular SSR with Node.js.
2. Attacker probes the endpoint to confirm the handling of URL matrix parameters (semicolons in path segments).
3. Attacker crafts a long request path containing multiple segments, each featuring repeated numeric matrix parameters (e.g., `;990;2522`).
4. Attacker sends multiple concurrent HTTP requests to the SSR endpoint, utilizing standard web-server buffer capacities (e.g., 2 KB to 8 KB path lengths).
5. The `@angular/router` component parses the URL, populating a `parameters` object with the malicious numeric keys.
6. V8 engine interprets these keys as dense array indices and allocates large, contiguous `HOLEY_ELEMENTS` backing stores for each segment.
7. Heap memory consumption spikes rapidly due to the 350x memory amplification.
8. Node.js process reaches the configured heap limit, triggering a process crash and resulting in a Denial of Service.

## Impact

Successful exploitation results in the termination of the SSR worker process, causing a service outage for users relying on server-side rendered content. An attacker can force this state with as few as 12 to 22 concurrent requests if the path length is near 8 KB, or 50 to 100 requests for smaller paths, effectively rendering the application unavailable.

## Recommendation

Prioritized actions for detection and remediation:
- Upgrade `@angular/router` to version 22.2.0, 21.2.24, 20.3.32, or later to address CVE-2026-101896.
- Configure upstream reverse proxies (Nginx, WAF) to block or strip semicolons (`;`) from incoming request URIs to prevent malicious parameters from reaching the Angular router.
- Implement strict request path segment limits at the edge to reduce the maximum possible heap allocation per request.
- Monitor SSR worker process memory usage via monitoring tools; sudden spikes in heap memory accompanied by high frequencies of semicolon-containing URLs indicate potential exploitation attempts.
