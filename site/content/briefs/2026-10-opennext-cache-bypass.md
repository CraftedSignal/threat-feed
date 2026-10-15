---
title: OpenNext Cloudflare Middleware Bypass via Cache Interception
slug: 2026-10-opennext-cache-bypass
description: The @opennextjs/cloudflare component contains a vulnerability (CVE-2026-100409) where inconsistent path decoding allows attackers to bypass middleware-based authorization and retrieve cached content.
date: "2026-10-15T22:24:22Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:opennext:opennextjs_cloudflare:*:*:*:*:*:*:*:*
tags:
  - web-application
  - middleware-bypass
  - cloudflare
  - cve-2026-100409
vendors:
  - OpenNext
products:
  - '@opennextjs/cloudflare (>= 0.3.0, < 1.20.2)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A remote unauthenticated attacker may retrieve cached content from routes intended to be protected by middleware.
    confidence_band: high
cves:
  - id: CVE-2026-100409
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-2vc4-c4r6-p6v6
  - https://github.com/opennextjs/opennextjs-aws/pull/1199
  - https://github.com/opennextjs/opennextjs-aws/pull/1200
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - AppSec
  immediate_actions:
    - action: Upgrade @opennextjs/cloudflare to 1.20.2 or later
      owner: IT Operations
      due: 48h
      evidence: Users should upgrade to @opennextjs/cloudflare@1.20.2 or later.
  mitigation_plan:
    - priority: immediate
      action: Disable enableCacheInterception in defineCloudflareConfig
      owner: AppSec
      addresses: CVE-2026-100409
      evidence: 'Disable cache interception by removing enableCacheInterception: true.'
---

A security vulnerability exists in `@opennextjs/cloudflare` versions 0.3.0 through 1.20.1 due to inconsistent percent-encoded path handling when the `enableCacheInterception` feature is activated. When enabled, the library performs path decoding during cache lookup that differs from the decoding logic used by middleware matchers.

This discrepancy allows an attacker to craft a request with percent-encoded characters that effectively hide the path from security middleware, while subsequently being normalized into a valid cache key that points to a protected resource. Because the middleware fails to trigger, the authorization check is skipped entirely, and the Cloudflare Worker serves the cached response directly to the unauthenticated user. The vulnerability also stems from a secondary issue where malformed segments are partially decoded rather than rejected, allowing for potential obfuscation. This flaw impacts applications relying on middleware for sensitive access control in conjunction with static asset caching.

## Impact

The vulnerability allows remote unauthenticated attackers to bypass intended access control mechanisms, resulting in the unauthorized retrieval of cached data from protected routes. The impact is limited to applications that explicitly enable `enableCacheInterception` and utilize middleware as their primary authorization gatekeeper. No specific victim counts are documented, but the scope includes all deployments of the affected `@opennextjs/cloudflare` package that meet these specific configuration criteria.

## Recommendation

* Upgrade `@opennextjs/cloudflare` to version 1.20.2 or later to address CVE-2026-100409.
* If immediate patching is not feasible, disable the `enableCacheInterception` setting in the `defineCloudflareConfig` object.
* Implement authorization logic directly within route handlers as a defense-in-depth measure, rather than relying solely on middleware.
* Validate and reject anomalous encoded paths at the edge using Cloudflare WAF rules before the request reaches the Worker environment.
