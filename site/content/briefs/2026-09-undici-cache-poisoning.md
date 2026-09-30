---
title: Cross-Origin Cache Poisoning Vulnerability in undici
slug: 2026-09-undici-cache-poisoning
description: The undici library (v8.10.0-v8.10.1) is vulnerable to cross-origin cache poisoning via interceptors.cache() and interceptors.deduplicate() due to insufficient origin isolation in cache key generation, allowing attackers to serve malicious responses to trusted origins.
date: "2026-09-30T04:19:25Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:nodejs:undici:*:*:*:*:*:node.js:*:*
products:
  - undici (>= 8.10.0, < 8.10.2)
cves:
  - id: CVE-2026-85152
    cvss: 7.4
    epss: 0.00211
references:
  - https://github.com/advisories/GHSA-vp8m-p9jh-q5pm
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-85152
action_plan:
  priority: elevated
  owners:
    - Development Teams
    - Application Security
  immediate_actions:
    - action: Upgrade undici to v8.10.2
      owner: Development Teams
      due: 48h
      evidence: Source explicitly identifies v8.10.2 as the patch version.
  mitigation_plan:
    - priority: immediate
      action: Isolate cache store and interceptor instances per origin
      owner: Development Teams
      addresses: CVE-2026-85152
      evidence: Source identifies instance sharing as the primary risk vector.
---

The undici HTTP client library is susceptible to cross-origin cache poisoning (CVE-2026-85152) due to an implementation flaw in how it constructs cache and deduplication keys within its interceptors. Specifically, the `interceptors.cache()` and `interceptors.deduplicate()` functions fail to incorporate the destination origin into the generated keys when a dispatcher lacks a single authoritative origin or when a request provides its own origin. 

This logic error enables an attacker who controls a response from a malicious or compromised origin to influence the cache entries for requests directed toward a different, trusted origin, provided the method, path, and relevant headers coincide. This vulnerability persists if a single cache store or interceptor instance is shared across multiple origins, facilitating cross-origin information disclosure or the poisoning of sensitive cached resources like JWKS (JSON Web Key Sets). The vulnerability was introduced in undici version 8.10.0 and affects versions 8.10.0 and 8.10.1.

## Impact

Applications that share an instance of `interceptors.cache()` or `interceptors.deduplicate()` across multiple, distinct origins are vulnerable. A successful exploit allows an attacker to perform persistent cache poisoning, which can result in the acceptance of attacker-signed tokens, leading to authentication bypass or unauthorized access. The scope of impact is contingent upon the application architecture and how extensively the vulnerable interceptor state is shared across network boundaries.

## Recommendation

1. Upgrade undici to version 8.10.2 or later immediately to resolve the underlying cache key generation flaw.
2. Audit application code to identify where `interceptors.cache()` or `interceptors.deduplicate()` instances are instantiated.
3. If immediate patching is not feasible, reconfigure the application to use separate cache stores and interceptor instances for every distinct origin, ensuring state isolation.
4. Ensure that `Agent` configurations, which are not impacted by this flaw, are used where feasible for origin-specific request handling.
