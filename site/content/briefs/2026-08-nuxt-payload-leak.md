---
title: Nuxt 4.x Runtime Payload Cache Disclosure
slug: 2026-08-nuxt-payload-leak
description: A vulnerability in Nuxt 4.4.0 through 4.5.0 causes sensitive SSR data in the payload cache to be disclosed to unauthorized users due to an insufficient cache key implementation.
date: "2026-08-05T21:25:24Z"
lastmod: "2026-08-06T03:25:58Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Nuxt
products:
  - Nuxt (4.4.0, 4.5.0)
  - nuxt (3.x)
  - nuxt (4.x)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: The internal island renderer endpoint (/__nuxt_island/...) decodes and hashes attacker-controlled request input before it validates the URL-resident hash, allowing a denial-of-service condition.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-wm8w-6qjm-cv43
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71316
  - https://github.com/advisories/GHSA-9pgf-384g-p7mv
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-71321
rules:
  - title: Detect Excessive Payload Size to Nuxt Island Endpoint
    description: Detects potential exploitation of CVE-2026-71321 by monitoring for large POST requests sent to the Nuxt island renderer endpoint, which may indicate a DoS attempt.
    platform: sigma
    severity: high
    tactics:
      - impact
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade all Nuxt 4.x applications to 4.5.1
      owner: IT Operations
      due: 24h
      evidence: Fixed in nuxt@4.5.1
  mitigation_plan:
    - priority: immediate
      action: Disable payload extraction or restrict access via proxy
      owner: IT Operations
      addresses: CVE-2026-71316
      evidence: Workaround provided by GHSA
updates:
  - at: "2026-08-06T03:25:58Z"
    level: L1
    summary: 'added detection rule: Detect Excessive Payload Size to Nuxt Island Endpoint'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-9pgf-384g-p7mv
---

Nuxt versions 4.4.0 through 4.5.0 contain a vulnerability (CVE-2026-71316) where the runtime payload cache incorrectly stores and retrieves data. The vulnerability resides in the `cache:nuxt:payload` storage, which utilizes a path-only cache key, ignoring session-specific context such as cookies, authorization headers, or cache variations. This allows an attacker to access sensitive SSR data by requesting the `/_payload.json` endpoint for routes that have been previously 'warmed' by an authenticated user. The SSR data typically includes results from `useFetch` or `useAsyncData`, which may contain private information like profile details, tenant identifiers, or billing data. The issue is specific to the 4.x release line and was caused by a regression where runtime payload-cache reads and writes were no longer restricted to the prerendering phase.

## Attack Chain

1. The target application is configured with `routeRules` using `cache`, `swr`, or `isr` on protected pages that display user-specific data.
2. An authenticated user accesses a protected, cached route, triggering the server to generate and store the SSR payload in the `cache:nuxt:payload` store.
3. The cached payload is stored using only the URL path as the key, lacking any session or authorization awareness.
4. An attacker or an unauthorized user identifies a target path that utilizes Nuxt payload extraction.
5. The attacker issues a `GET` request to `/<target-path>/_payload.json`.
6. The Nuxt renderer retrieves the stored payload from the shared cache before any route middleware, page guards, or authorization checks are executed.
7. The sensitive payload, intended only for the original authenticated user, is returned to the unauthorized requester in the response body.

## Impact

Successful exploitation leads to unauthorized access to sensitive application data rendered during SSR. This exposure impacts users across different sessions, including the disclosure of profile information, billing details, and internal application data to unauthenticated clients. Any application relying on Nuxt 4.4.0-4.5.0 with caching enabled on authenticated routes is at risk.

## Recommendation

* Upgrade to `nuxt@4.5.1` immediately to restore proper prerendering gates on payload caching.
* If upgrading is not immediately feasible, set `experimental.payloadExtraction: false` in the Nuxt configuration to disable the vulnerable endpoint.
* Audit `routeRules` to remove `cache`, `swr`, or `isr` configurations from pages that display user-specific data.
* Implement authentication requirements at the edge, such as CDN or proxy-level, specifically for `/**/_payload.json` paths as a temporary defense-in-depth measure.
* Purge CDN and platform caches after applying security updates to ensure potentially leaked payloads are removed from intermediate storage.
