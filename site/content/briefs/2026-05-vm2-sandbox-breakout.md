---
title: VM2 Sandbox Breakout Vulnerability via Promise Species Manipulation (CVE-2026-47208)
slug: 2026-05-vm2-sandbox-breakout
description: VM2 is vulnerable to a sandbox breakout vulnerability (CVE-2026-47208) that allows attackers to execute arbitrary commands on the host system by manipulating Promise species and escaping the sandbox context.
date: "2026-05-29T17:41:49Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vm2
  - sandbox-escape
  - rce
vendors:
  - npm
products:
  - vm2 (<= 3.11.3)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218.007
    technique_name: Signed Binary Proxy Execution
references:
  - https://github.com/advisories/GHSA-76w7-j9cq-rx2j
rules:
  - title: Detect VM2 Sandbox Escape via Promise Species Manipulation
    description: Detects CVE-2026-47208 exploitation - execution of `child_process.execSync` within the vm2 sandbox indicating a sandbox escape attempt.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1218.007
    data_sources:
      - process_creation
      - linux
  - title: Detect VM2 Sandbox Escape via Promise Species Manipulation (Windows)
    description: Detects CVE-2026-47208 exploitation - execution of `child_process.execSync` within the vm2 sandbox on Windows, indicating a sandbox escape attempt.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1218.007
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A critical sandbox breakout vulnerability (CVE-2026-47208) has been identified in vm2 versions 3.11.3 and earlier. This flaw allows an attacker with the ability to execute arbitrary code within the vm2 sandbox to escape the sandbox and achieve arbitrary code execution on the host system. The vulnerability arises due to a missing `resetPromiseSpecies` call within the `localPromise` constructor when handling rejected promises, leading to the possibility of injecting a custom promise with a specially crafted reject method. This bypasses the intended security boundaries of the vm2 sandbox.

## Attack Chain

1.  Attacker gains initial code execution within the vm2 sandbox environment.
2.  Attacker defines a custom `FakePromise` class with a getter for `Symbol.species` that returns a custom constructor `ct`.
3.  Attacker defines a function `doCatch` that takes a function `f` as input and creates a new Promise using `Promise.withResolvers()`.
4.  The custom constructor `ct` is assigned to the `Symbol.species` of the `FakePromise` class within the `doCatch` function. The `ct` constructor defines how the promise will be resolved or rejected, intercepting errors.
5.  The `FakePromise` constructor is called with a resolver function, allowing the custom reject method in `ct` to get called when a promise is rejected.
6.  The attacker triggers an error within the sandbox (e.g., a `RangeError` by overflowing the stack). The custom reject method in `ct` intercepts the error, determines if it is a `RangeError` and not a standard Error object, and then executes host commands using `child_process.execSync('touch pwned')`.
7.  A file named `pwned` is created on the host system, demonstrating successful code execution outside the sandbox.
8.  The attacker now has arbitrary code execution on the host system.

## Impact

Successful exploitation of CVE-2026-47208 allows an attacker to bypass the vm2 sandbox and execute arbitrary code on the host system. This can lead to complete system compromise, data theft, or denial-of-service. The severity is critical due to the ease of exploitation and the potential for widespread impact on applications relying on vm2 for sandboxing untrusted code. The number of victims depends on the adoption of the vulnerable vm2 package.

## Recommendation

*   Upgrade to vm2 version 3.11.4 or later to patch CVE-2026-47208.
*   Deploy the Sigma rule "Detect VM2 Sandbox Escape via Promise Species Manipulation" to detect exploitation attempts by monitoring for the execution of `child_process.execSync` within the vm2 sandbox.
*   Review and restrict the use of vm2 in environments where untrusted code execution is a significant risk.
