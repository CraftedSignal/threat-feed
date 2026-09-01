---
title: Browserslist Unbounded Memory Growth via Cache Exhaustion
slug: 2026-09-browserslist-oom
description: The Browserslist package is vulnerable to a volumetric denial-of-service attack due to a missing cache eviction policy in its internal query result storage, leading to unbounded heap growth and potential OOM crashes in long-running processes.
date: "2026-09-01T18:00:21Z"
lastmod: "2026-09-01T18:00:44Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:browserslist:browserslist:*:*:*:*:*:node.js:*:*
tags:
  - denial-of-service
  - memory-exhaustion
  - javascript
  - nodejs
  - vulnerability
  - prototype-pollution
  - supply-chain
products:
  - browserslist (<= 4.28.6)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: The Browserslist library is vulnerable to prototype pollution and a denial-of-service (DoS) condition caused by insufficient validation of the 'browserslist-stats.json' file or 'opts.stats' input.
    confidence_band: high
cves:
  - id: CVE-2026-73089
    cvss: 7.5
    epss: 0.0036
references:
  - https://github.com/advisories/GHSA-c83g-rgw3-j3cx
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73089
  - https://github.com/advisories/GHSA-73wf-gq98-2v4g
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-73088
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  mitigation_plan:
    - priority: immediate
      action: Upgrade browserslist to 4.28.7 or later
      owner: IT Operations
      addresses: CVE-2026-73089
      evidence: Source provides fix logic using Map and CACHE_MAX_ENTRIES limit.
updates:
  - at: "2026-09-01T18:00:44Z"
    level: L1
    summary: added coverage for browserslist (<= 4.28.6)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-73wf-gq98-2v4g
---

The Browserslist package (up to and including v4.28.6) contains a memory management vulnerability in its internal query and parse caches. The application maintains two objects, `cache` and `parseCache`, which store results indexed by query keys generated via `JSON.stringify()`. These caches lack size constraints, time-to-live (TTL) policies, or eviction mechanisms, and are not cleared by the `browserslist.clearCaches()` function. 

In long-running Node.js processes such as web servers or CI workers, an attacker who can influence the query strings passed to `browserslist()` can cause unbounded memory growth. Specifically, the `since <year>-<month>-<day>` query pattern allows for a large space of valid, distinct keys. By sending a high volume of unique requests, an attacker can force the accumulation of cache entries until the process exhausts available heap memory, resulting in an out-of-memory (OOM) crash. Analysis showed an approximately 150x memory amplification factor, where 20,000 distinct queries consumed over 50 MB of permanent heap space.

## Attack Chain

1. Attacker identifies a target application utilizing Browserslist in a long-running process (e.g., web server or CI pipeline) that accepts user-influenced input for browser queries.
2. Attacker crafts a series of distinct, syntactically valid `since <year>-<month>-<day>` query strings.
3. Attacker sends a high volume of requests to the target, each containing a unique date variation to ensure the cache key is novel.
4. The target application passes these queries to the `browserslist()` function.
5. The library generates a unique `cacheKey` using `JSON.stringify()` for each request.
6. Browserslist stores the resulting data in the unbounded `cache` and `parseCache` objects.
7. Memory usage of the process grows linearly with the number of unique queries.
8. Upon reaching memory limits, the process crashes due to an OOM condition, resulting in a denial-of-service.

## Impact

Successful exploitation results in a denial-of-service via process termination. This vulnerability impacts long-running Node.js applications that process external inputs influencing browser queries. The attack requires a sustained, high-volume request stream rather than a single malicious payload, which characterizes it as a volumetric DoS.

## Recommendation

1. Upgrade the `browserslist` package to a version that implements the bounded cache fix (e.g., > 4.28.6).
2. If an immediate upgrade is not possible, review application code to identify if user input influences `browserslist()` calls and implement an application-layer cache proxy or query validation to restrict the variety of permitted query strings.
3. Ensure that if `BROWSERSLIST_DISABLE_CACHE` is used as a workaround, the impact on performance is measured against the expected request load.
