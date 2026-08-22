---
title: Arbitrary Code Execution in JSONata
slug: 2026-08-jsonata-rce
description: The JSONata library contains a critical vulnerability (CVE-2026-77415) allowing unauthenticated attackers to achieve arbitrary code execution via maliciously crafted JSONata expressions.
date: "2026-08-22T01:16:22Z"
lastmod: "2026-08-22T01:16:31Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - remote-code-execution
  - cve-2026-77415
  - software-vulnerability
  - nodejs
products:
  - jsonata (>= 2.0.0, < 2.2.1)
  - jsonata (< 1.8.8)
  - jsonata (2.0.0 to 2.2.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Which could be chained to execute arbitrary code.
    confidence_band: high
cves:
  - id: CVE-2026-77415
references:
  - https://github.com/advisories/GHSA-66mm-25pp-rfff
  - https://github.com/jsonata-js/jsonata/pull/799
  - https://github.com/jsonata-js/jsonata/pull/800
  - https://github.com/jsonata-js/jsonata/pull/802
  - https://github.com/advisories/GHSA-2943-5xfg-gq5f
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77414
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade jsonata dependency to v2.2.1 or v1.8.8
      owner: Application Security
      due: 24h
      evidence: Source advisory confirms patch versions
  mitigation_plan:
    - priority: immediate
      action: Identify applications evaluating user-supplied JSONata expressions
      owner: Application Security
      addresses: CVE-2026-77415
      evidence: Vulnerability analysis
updates:
  - at: "2026-08-22T01:16:31Z"
    level: L2
    summary: added coverage for jsonata (2.0.0 to 2.2.0) +1 products
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-2943-5xfg-gq5f
---

JSONata versions prior to 2.2.1 and 1.8.8 are vulnerable to arbitrary code execution due to flaws in how the library processes and executes transformation expressions. An attacker can chain three specific vulnerabilities to escape the sandboxed environment: the ability to overwrite the internal `$clone` function, the ability to destruct internal JSONata lambdas, and an unsafe implementation of `forEach` within the `applyProcedure` function. By manipulating these primitives, an attacker can prototype-pollute the execution context and access Node.js built-in modules, such as `child_process`. This allows the execution of arbitrary system commands on the host running the JSONata engine. This vulnerability, tracked as CVE-2026-77415, poses a significant risk to applications that process untrusted user-supplied JSONata expressions.

## Attack Chain

1. Attacker identifies an application endpoint that accepts and evaluates user-provided JSONata expressions.
2. Attacker submits a crafted JSONata payload that overwrites the `$clone` function to permit object mutation.
3. Attacker uses `$merge` to destruct internal JSONata functions or lambdas, enabling access to the execution context.
4. Attacker performs prototype pollution using the manipulated objects to access `__lookupGetter__`.
5. Attacker exploits the unsafe `forEach` implementation in `applyProcedure` to further refine the execution environment.
6. Attacker leverages the modified environment to bridge into the Node.js runtime and access the `child_process` built-in module.
7. Attacker executes system-level commands, such as `execSync('sh')`, to achieve full remote code execution.

## Impact

Successful exploitation of CVE-2026-77415 allows for complete system compromise on any server running vulnerable versions of the JSONata library. The vulnerability affects all applications that allow users to submit dynamic JSONata queries, including data processing platforms, API transformation layers, and automation engines. Organizations using vulnerable versions should prioritize patching to 2.2.1 or 1.8.8 immediately to mitigate the risk of arbitrary command execution.

## Recommendation

- Update the jsonata package to version 2.2.1 or 1.8.8 across all affected applications immediately.
- Implement strict input validation or sandboxing for any interface that evaluates user-supplied JSONata expressions.
- Scan dependencies to identify all instances of the vulnerable jsonata package within the software supply chain.
