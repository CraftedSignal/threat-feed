---
title: Arbitrary Code Execution in Faker.js helpers.fake
slug: 2026-09-faker-rce
description: The Faker.js library contains an arbitrary code execution vulnerability in the helpers.fake method, allowing attackers to access the global constructor and execute unauthorized JavaScript.
date: "2026-09-02T18:06:25Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:fakerjs:faker:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - javascript
vendors:
  - Faker.js
products:
  - faker (<= 10.4.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The faker.helpers.fake method can be tricked into arbitrary code execution.
    confidence_band: high
cves:
  - id: CVE-2026-73231
    cvss: 7.8
    epss: 0.00154
references:
  - https://github.com/advisories/GHSA-qxc2-j82w-r537
action_plan:
  priority: elevated
  owners:
    - Development
    - Security Operations
  immediate_actions:
    - action: Upgrade @faker-js/faker to a patched version post-10.4.0
      owner: Development
      due: 48h
      evidence: CVE-2026-73231
  mitigation_plan:
    - priority: immediate
      action: Review codebases for untrusted input passed to faker.helpers.fake
      owner: Development
      addresses: CVE-2026-73231
      evidence: Affected products report
---

Faker.js versions 10.4.0 and earlier are vulnerable to an arbitrary code execution flaw within the `helpers.fake` method, tracked as CVE-2026-73231. The vulnerability exists due to improper property resolution logic in `fakeEval.resolveProperty`. Specifically, the function attempts to resolve properties on functions directly rather than performing a recursive resolution. This logic error allows attackers to traverse and access the `constructor` of objects, providing a path to execute arbitrary JavaScript code. 

The library documentation explicitly claims that it is not possible to use non-faker methods or plain JavaScript within fake template strings; however, this vulnerability proves that global objects remain accessible. An attacker can craft a template string containing a payload such as `{{test.constructor(alert('Code Execution'))}}` to escape the intended sandbox. This impacts any application that processes user-supplied or untrusted strings through the `helpers.fake` function.

## Impact

The vulnerability allows for remote code execution in any environment where an attacker can influence the template string passed to the `helpers.fake` method. This affects all applications leveraging Faker.js versions 10.4.0 and below. If an application uses this method to process inputs from end-users or external sources, an attacker could achieve full code execution within the Node.js or browser environment, potentially leading to data exfiltration or unauthorized system access.

## Recommendation

- Upgrade the `@faker-js/faker` package to a version beyond 10.4.0 immediately to resolve CVE-2026-73231.
- Audit all application codebases for instances where user-supplied or external input is passed directly into the `faker.helpers.fake` method.
- If upgrading is not immediately feasible, sanitize all input strings passed to `helpers.fake` to block characters and patterns that could facilitate access to the `constructor` property or other global objects.
