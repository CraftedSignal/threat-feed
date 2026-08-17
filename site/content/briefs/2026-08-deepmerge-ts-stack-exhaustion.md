---
title: Stack Exhaustion Vulnerability in deepmerge-ts
slug: 2026-08-deepmerge-ts-stack-exhaustion
description: The deepmerge-ts library contains a stack exhaustion vulnerability, CVE-2026-40345, that allows attackers to trigger a process crash by providing crafted, self-referencing recursive object graphs to merge functions.
date: "2026-08-17T18:47:21Z"
type: advisory
types:
  - advisory
severities:
  - medium
products:
  - deepmerge-ts (< 8.0.0)
references:
  - https://github.com/advisories/GHSA-ggr8-5vv4-36mx
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40345
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade deepmerge-ts to 8.0.0+
      owner: IT Operations
      due: 72h
      evidence: Source advisory recommends upgrading to version 8.0.0
  mitigation_plan:
    - priority: immediate
      action: Review application code paths where user input is passed to deepmerge-ts functions
      owner: Application Security
      addresses: CVE-2026-40345
      evidence: Vulnerability is reachable through public APIs deepmerge and deepmergeInto
---

The deepmerge-ts library (versions prior to 8.0.0) is susceptible to a denial-of-service attack due to a flaw in its recursive object merging logic. The library recursively traverses object trees to perform merges but lacks cycle detection or tracking for visited object pairs. An attacker who can influence the input objects passed to functions such as `deepmerge()`, `deepmergeInto()`, or their custom variations can provide a crafted object graph containing self-references. When the library attempts to merge these structures, it enters an infinite recursion, eventually causing the Node.js runtime to throw a 'RangeError: Maximum call stack size exceeded'. This vulnerability impacts applications that allow users to submit complex or serialized objects for server-side processing, potentially leading to repeated service crashes and availability loss.

## Impact

Applications that process attacker-supplied object structures using vulnerable versions of deepmerge-ts are at risk of a synchronous service crash. In Node.js-based environments, this can lead to unhandled exceptions that terminate the process. In clustered or managed environments, this may trigger frequent worker restarts, effectively creating a persistent denial-of-service state for the targeted application endpoint.

## Recommendation

- Upgrade the deepmerge-ts dependency to version 8.0.0 or later to include the required cycle detection logic.
- Audit all application endpoints that accept user-provided JSON or object structures for processing to ensure input is validated before being passed to deepmerge-ts.
- Monitor logs for repeated 'RangeError: Maximum call stack size exceeded' exceptions linked to application processes to identify potential exploitation attempts.
