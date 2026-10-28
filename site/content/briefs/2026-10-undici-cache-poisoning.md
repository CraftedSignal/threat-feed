---
brief_id: brief-2026-10-27-undici-cache-poisoning
event_id: brief-2026-10-27-undici-cache-poisoning
revision: 1
activity_at: "2026-10-27T23:58:35Z"
title: 'undici: Cache poisoning and cross-user data disclosure via cross-origin redirects (CVE-2026-109829)'
slug: 2026-10-undici-cache-poisoning
description: The undici library is vulnerable to cache poisoning and unauthorized cross-user data disclosure due to improper cache key generation when using shared cache interceptors after redirect handlers.
date: "2026-10-27T23:58:35Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source-verified
cpes:
  - cpe:2.3:a:nodejs:undici:*:*:*:*:*:*:*:*
  - cpe:2.3:a:nodejs:undici:*:*:*:*:*:node.js:*:*
vendors:
  - Node.js
products:
  - undici (< 7.30.1)
  - undici (>= 8.0.0, < 8.12.2)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1565
    technique_name: Data Manipulation
    subtechnique_id: T1565.001
    subtechnique_name: Stored Data Manipulation
    evidence: An attacker who controls the target of a redirect from a trusted URL can have their response cached under that trusted URL.
    confidence_band: high
cves:
  - id: CVE-2026-109829
    cvss: 7.4
    epss: 0.00149
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-4w7w-5xrc-9h26
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch undici dependency to 7.30.1 or 8.12.2
      owner: IT Operations
      due: 48h
      evidence: Upgrade to 7.30.1 or 8.12.2.
  hunt_leads:
    - lead: Identify applications utilizing undici versions in the affected range and inspect source code for the interceptor composition pattern.
      technique_id: T1565.001
      data_needed:
        - Application dependency manifests (package.json, lock files)
        - Application source code
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Applications are affected only when an originless Agent, a shared MemoryCacheStore or SqliteCacheStore, and the composition compose(redirect(), cache()) are all used.
  mitigation_plan:
    - priority: immediate
      action: Change interceptor composition order to compose(cache(), redirect())
      owner: IT Operations
      addresses: CVE-2026-109829
      evidence: Compose the interceptors as compose(cache(), redirect()), use per-origin dispatchers and cache stores, or disable shared caching on redirect-capable requests.
---

The undici HTTP client library contains a vulnerability (CVE-2026-109829) in its cache interceptor when used in conjunction with the redirect interceptor. Specifically, when an originless Agent is configured with the interceptor composition `compose(redirect(), cache())` and a shared cache, the cache key is generated based on the original request URL before the redirect occurs. 

This allows the response from a cross-origin redirect to be stored under the key of the initial trusted URL. An attacker controlling the redirect target can poison the cache with malicious content, or cause private, user-specific data to be stored and served to unauthenticated callers if the redirect path contains sensitive information. The vulnerability affects versions 7.x (< 7.30.1) and 8.x (< 8.12.2).

## Impact

Successful exploitation allows for persistent cache poisoning of trusted URLs or the disclosure of sensitive, private data across users within the same shared cache instance.

## Recommendation

- Upgrade `undici` to version `7.30.1` or `8.12.2` immediately.
- If upgrading is not immediately possible, update the interceptor composition order to `compose(cache(), redirect())`.
- Ensure the use of per-origin dispatchers (`Client` or `Pool`) or disable shared caching for requests that are susceptible to redirects.
