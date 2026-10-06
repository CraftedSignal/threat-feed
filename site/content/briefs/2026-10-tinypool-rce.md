---
title: Tinypool Prototype Pollution Leads to Remote Code Execution
slug: 2026-10-tinypool-rce
description: A prototype pollution vulnerability in the tinypool Node.js worker pool library allows attackers to gain arbitrary code execution in child processes by injecting worker configuration options.
date: "2026-10-06T00:42:28Z"
lastmod: "2026-10-06T00:42:36Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:tinypool_project:tinypool:*:*:*:*:*:node.js:*:*
tags:
  - supply-chain
  - rce
  - prototype-pollution
  - javascript
products:
  - tinypool (<= 2.1.0)
  - tinypool (< 2.1.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: By polluting these properties, an attacker can force worker threads to load arbitrary JavaScript files, leading to remote code execution in the context of the host process.
    confidence_band: high
cves:
  - id: CVE-2026-104848
    epss: 0.00497
references:
  - https://github.com/advisories/GHSA-5gmw-xhrv-c9v3
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104848
  - https://github.com/advisories/GHSA-85c8-ppgw-ccpr
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104849
action_plan:
  priority: immediate_escalation
  owners:
    - Security Operations
    - DevOps Engineering
  immediate_actions:
    - action: Audit build environments and CI/CD pipelines for tinypool versions <= 2.1.0 and mandate an immediate upgrade to the patched release.
      owner: DevOps Engineering
      due: 24h
      evidence: CVE-2026-104848 affects tinypool versions <= 2.1.0.
  mitigation_plan:
    - priority: immediate
      action: Update tinypool to 2.1.1 or later
      owner: IT Operations
      addresses: CVE-2026-104848
      evidence: Suggested fix in GHSA-5gmw-xhrv-c9v3.
updates:
  - at: "2026-10-06T00:42:36Z"
    level: L2
    summary: added coverage for tinypool (< 2.1.2)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-85c8-ppgw-ccpr
---

Tinypool, a worker pool implementation used by high-traffic packages like Vitest, is vulnerable to a prototype pollution attack (CVE-2026-104848) that enables remote code execution. The vulnerability exists because the library explicitly reads worker configuration options (such as 'execArgv' and 'env') from objects that may contain prototype-inherited properties. By polluting 'Object.prototype' with these keys, an attacker can override the library's intended settings. When tinypool spawns a worker thread, it reads these polluted values and passes them as explicit arguments to the Node.js 'worker_threads.Worker' constructor. This re-materialization of inherited properties defeats Node.js core security mechanisms, allowing an attacker to force workers to load arbitrary malicious scripts or inject 'NODE_OPTIONS' into the worker environment. This threat is particularly dangerous in CI/CD pipelines or build environments, where an attacker who gains a prototype-pollution primitive in any dependency can gain execution privileges equivalent to the build host.

## Attack Chain

1. Attacker identifies a prototype pollution sink in an application dependency (e.g., via a library like lodash or minimist) that allows modifying 'Object.prototype'.
2. Attacker injects a malicious payload into 'Object.prototype.execArgv' or 'Object.prototype.env'.
3. Attacker triggers a feature in the target application that initializes a new 'Tinypool' instance.
4. Tinypool constructor runs, merging 'this.options' via object spread, effectively converting the prototype-inherited properties into own-properties of the configuration object.
5. The library passes these polluted properties to the internal 'worker_threads.Worker' instantiation logic.
6. Node.js initiates a new worker process utilizing the attacker-supplied '--require' argument or 'NODE_OPTIONS' environment variable.
7. The worker process executes the attacker's script upon startup with the same permissions as the parent process.
8. Attacker gains full remote code execution within the host environment, potentially accessing secrets, keys, or source code.

## Impact

Successful exploitation allows arbitrary code execution with the privileges of the host process. Given tinypool's widespread use as the default worker pool for Vitest (averaging 42 million downloads per week), the primary impact is widespread supply-chain compromise. Attackers can target developer machines or CI/CD runners to exfiltrate environment secrets, steal signing keys, or inject malicious code into build artifacts.

## Recommendation

1. Upgrade all instances of tinypool to a version that implements own-property semantics for worker configuration (ensure the library is patched past version 2.1.0).
2. Use 'Object.create(null)' for configuration object initialization to prevent prototype chain lookups.
3. Audit dependencies for known prototype pollution vulnerabilities using static analysis tools to identify potential source gadgets.
4. Implement runtime protection or monitor for suspicious 'NODE_OPTIONS' or process argument injections in build and test process trees.
