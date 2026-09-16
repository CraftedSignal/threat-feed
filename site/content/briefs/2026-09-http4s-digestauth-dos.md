---
title: Denial of Service via Heap Exhaustion in http4s DigestAuth
slug: 2026-09-http4s-digestauth-dos
description: An improper eviction logic in the http4s DigestAuth middleware allows unauthenticated remote attackers to cause heap exhaustion and service failure by triggering unbounded growth of the internal nonce map.
date: "2026-09-16T01:05:52Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:http4s:http4s_ember_server:*:*:*:*:*:*:*:*
vendors:
  - http4s
products:
  - http4s-ember-server (<= 0.23.34, 1.0.0-M1 <= 1.0.0-M46)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An attacker can drive the nonce map to grow without bound until the JVM runs out of heap.
    confidence_band: high
cves:
  - id: CVE-2026-69208
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-fm4g-76c9-7w69
  - https://nvd.nist.gov/vuln/detail/CVE-2026-69208
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Upgrade http4s-ember-server to 0.23.35 or later
      owner: Development
      due: 48h
      evidence: Source states fix involves corrected eviction logic and max cache size.
  mitigation_plan:
    - priority: immediate
      action: Front DigestAuth routes with a request rate limiter.
      owner: IT Operations
      addresses: CVE-2026-69208
      evidence: Workaround suggested in source documentation.
---

The http4s `DigestAuth` server middleware contains a vulnerability in its stale-nonce cleanup mechanism, documented as CVE-2026-69208. The logic responsible for removing stale nonces uses an inverted comparison, resulting in the removal of fresh nonces while retaining stale ones indefinitely. Since the middleware generates a new nonce for every unauthenticated challenge, an attacker can intentionally flood a vulnerable service with requests to populate the nonce map. Because the stale nonces are never properly evicted, the map grows without bound until the Java Virtual Machine (JVM) experiences heap exhaustion and terminates due to an OutOfMemoryError. This vulnerability affects multiple versions of `http4s-ember-server`, including the 0.23.x series up to and including 0.23.34 and the 1.0.0 milestone series from 1.0.0-M1 through 1.0.0-M46. Organizations using DigestAuth should prioritize upgrading to the patched versions where the eviction logic has been corrected and a hard cache limit has been implemented.

## Impact

Successful exploitation results in a persistent denial-of-service condition for the affected JVM process. This vulnerability impacts any service utilizing `DigestAuth` on its routes, potentially leading to widespread service unavailability if the application is targeted by high-volume, unauthenticated request bursts. Given the nature of the heap exhaustion, the leak is persistent and cannot be self-corrected by the application, requiring manual intervention or restarts to restore service until a patch is applied.

## Recommendation

- Upgrade `http4s-ember-server` to the latest version where the cache eviction logic is corrected and the 1,000,000 entry limit is imposed.
- Implement a rate limiter in front of all routes protected by `DigestAuth` to mitigate the speed at which the nonce map can be filled while transitioning to patched versions.
- Configure monitoring for JVM heap utilization to identify early indicators of memory growth associated with nonce map exhaustion.
- Review application configurations to ensure that `DigestAuth` is only applied to routes that require authentication.
