---
brief_id: brief-2026-10-26-graphql-tools-prototype-pollution-9385e300
event_id: brief-2026-10-26-graphql-tools-prototype-pollution-9385e300
revision: 1
activity_at: "2026-10-26T16:13:58Z"
title: '@graphql-tools/utils: Prototype pollution in mergeIncrementalResult'
slug: 2026-10-graphql-tools-prototype-pollution-9385e300
description: A prototype pollution vulnerability in @graphql-tools/utils allows an attacker to inject arbitrary properties into Object.prototype via unvalidated path segments in incremental GraphQL responses.
date: "2026-10-26T16:13:58Z"
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
tags:
  - prototype-pollution
  - supply-chain
  - graphql
vendors:
  - Ardatan
products:
  - '@graphql-tools/utils (>= 10.10.1, <= 12.0.1)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A malicious, compromised, or MITM'd upstream can choose the path value and therefore choose global prototype keys and values in the gateway or client process.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-c4qx-w738-7hr3
action_plan:
  priority: elevated
  owners:
    - SOC
    - Application Security
  immediate_actions:
    - action: Audit Node.js applications utilizing @graphql-tools/utils for processing external or untrusted GraphQL incremental responses.
      owner: Application Security
      due: 48h
      evidence: The documented happy path of the exported helper is affected.
  hunt_leads:
    - lead: Identify applications using @graphql-tools/utils that consume untrusted GraphQL incremental responses.
      technique_id: T1190
      data_needed:
        - Application dependency manifests (package.json)
        - Code audit for usage of mergeIncrementalResult
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The entry point is the public API mergeIncrementalResult, exported directly for consumers that assemble incremental transport results.
  mitigation_plan:
    - priority: immediate
      action: Implement primitive-type validation for path segments before calling mergeIncrementalResult.
      owner: Application Security
      addresses: Prototype pollution in @graphql-tools/utils
      evidence: Validate the type of every path segment before it is used for property access.
---

The `@graphql-tools/utils` package (versions 10.10.1 through 12.0.1) contains a prototype pollution vulnerability in the `mergeIncrementalResult` function. The function incorrectly validates path segments by using strict equality checks (`===`) against forbidden keys like `'__proto__'`, `'constructor'`, and `'prototype'`. Because the function does not verify that these path segments are primitive types (strings or numbers), an attacker can supply an object, such as an array `["__proto__"]`. In JavaScript, this is coerced into the string `"__proto__"` during property access, successfully bypassing the protection check and allowing the attacker to write values onto `Object.prototype`. This can lead to authorization bypass, configuration manipulation, or unexpected application behavior in any consuming Node.js process.

## Attack Chain

1. An attacker gains control over, or performs a MITM attack on, an upstream GraphQL subgraph or transport layer.
2. The attacker crafts a malicious incremental GraphQL response (such as an `@defer` or `@stream` patch).
3. The attacker sets the `path` field in the response to include a non-primitive, array-based segment: `[["__proto__"], "maliciousKey"]`.
4. The consuming application receives the malicious response and passes it to the public `mergeIncrementalResult` helper.
5. `mergeIncrementalResult` calls `setObjectKeyPath`, which checks the array `["__proto__"]` against the forbidden strings; the check fails (returning false) because the types do not match, allowing the segment to proceed.
6. During assignment, `current[key]` triggers `ToPropertyKey` coercion, converting the array to the string `"__proto__"`.
7. The function resolves `Object.prototype` and assigns the attacker's value to the chosen key.
8. Unrelated objects created subsequently in the Node.js process inherit the polluted property, altering application logic.

## Impact

An attacker can overwrite properties on `Object.prototype`, potentially impacting global application security controls (e.g., overriding `isAdmin` flags or configuration objects). This effect persists for the lifetime of the Node.js process and applies to all objects instantiated after the pollution event, escaping the scope of the original GraphQL response.

## Recommendation

* Upgrade `@graphql-tools/utils` to a patched version once available, or implement a wrapper to validate that all path segments are strictly primitive strings or numbers before calling `mergeIncrementalResult`.
* Use `Object.freeze(Object.prototype)` in the consuming Node.js application to mitigate the impact of prototype pollution attempts.
* Implement runtime input validation on all upstream data sources that provide incremental GraphQL responses.
