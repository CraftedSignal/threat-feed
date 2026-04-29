---
title: SandboxJS Integrity Escape Vulnerability
slug: 2026-04-sandboxjs-escape
description: A sandbox integrity escape vulnerability exists in SandboxJS versions prior to 0.8.36, allowing untrusted code to bypass global write protections and mutate host shared global objects, potentially leading to cross-context persistence and broader compromise.
date: "2026-04-03T21:44:39Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - sandbox-escape
  - javascript
  - vulnerability
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-2gg9-6p7w-6cpj
rules:
  - title: Detect SandboxJS Global Object Mutation via Constructor Call
    description: Detects the usage of `this.constructor.call` to modify global objects, indicating a potential SandboxJS escape attempt.
    platform: sigma
    severity: critical
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect SandboxJS Constructor Call to Global Objects
    description: Detects calls to the constructor of a SandboxJS object targeting global objects such as Math or JSON.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical vulnerability exists in SandboxJS versions prior to 0.8.36, a JavaScript sandbox library. This vulnerability allows malicious or untrusted JavaScript code executed within the sandbox to escape the sandbox and modify global objects in the host environment. The bypass is achieved through an exposed callable constructor path: `this.constructor.call(target, attackerObject)`, allowing attackers to circumvent intended protections against direct assignment to global objects. This can lead to persistent modifications of host runtime state and cross-context contamination. Successful exploitation could allow attackers to compromise other requests, tenants, or subsequent sandbox runs within the same process, potentially leading to control-flow hijack in application logic that assumes trusted built-in behavior.

## Attack Chain

1.  The attacker injects JavaScript code into the SandboxJS environment.
2.  The injected code gains access to the `SandboxGlobal` constructor via `this.constructor`.
3.  The attacker leverages `Function.prototype.call` to invoke the `SandboxGlobal` constructor with a target global object (e.g., `Math`, `JSON`) and a payload object containing properties to overwrite.
4.  The `SandboxGlobal` constructor copies properties from the attacker-controlled payload object into the specified global object in the host environment, bypassing the intended write-time checks.
5.  The host environment's global object is modified with attacker-supplied values.
6.  Subsequent executions of SandboxJS instances within the same process now operate with the tainted global object.
7.  If the host application relies on the integrity of the mutated global objects, attacker can hijack control flow.
8.  The attacker achieves code execution in the host environment due to the modified global state.

## Impact

This vulnerability allows untrusted code to escape the SandboxJS sandbox and directly manipulate the host environment's global objects. This can lead to a variety of impacts, including persistent cross-context contamination, where new sandbox instances are initialized with a tainted state. The modification of critical global objects can lead to unpredictable behavior and, in certain scenarios, enable complete control-flow hijack of the host application. The severity of the impact is considered critical due to the potential for widespread and persistent compromise. Affected versions: npm/@nyariv/sandboxjs (vulnerable: < 0.8.36).

## Recommendation

*   Upgrade to SandboxJS version 0.8.36 or later to patch the vulnerability (Affected Packages).
*   Implement monitoring for unexpected modifications to global objects within the host environment where SandboxJS is deployed (see rule "Detect SandboxJS Global Object Mutation via Constructor Call").
*   Consider implementing additional layers of defense, such as restricting the capabilities of the host environment where SandboxJS is running, to minimize the impact of a successful sandbox escape (see rule "Detect SandboxJS Constructor Call to Global Objects").
*   Review host application code that relies on global objects and consider implementing validation checks to ensure their integrity (see CVE-2026-34208).
