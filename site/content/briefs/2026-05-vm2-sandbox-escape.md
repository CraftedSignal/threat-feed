---
title: vm2 Sandbox Escape via Prototype Pollution
slug: 2026-05-vm2-sandbox-escape
description: A vulnerability in vm2 versions 3.9.6 through 3.10.5 allows attacker-controlled JavaScript running in a default VM or inherited NodeVM to mutate shared host prototypes from inside the sandbox, leading to sandbox escape and prototype pollution.
date: "2026-05-07T04:07:05Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sandbox-escape
  - prototype-pollution
  - javascript
products:
  - vm2 (3.9.6 - 3.10.5)
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
  - https://github.com/advisories/GHSA-vwrp-x96c-mhwq
rules:
  - title: Detect VM2 Prototype Access
    description: Detects attempts to access the __proto__ property within a vm2 sandbox, which may indicate a prototype pollution attack.
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
  - title: Detect VM2 Prototype Modification
    description: Detects modifications to the Object.prototype, Array.prototype, or Function.prototype within a vm2 sandbox.
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
rules_count: 2
---

The vm2 library, a popular sandbox environment for Node.js, is vulnerable to a prototype pollution attack. Versions 3.9.6 through 3.10.5 are affected. This vulnerability allows malicious JavaScript code running within the vm2 sandbox to escape the sandbox and modify the prototypes of core JavaScript objects (Object, Array, Function) in the host environment. This is possible due to the library's bridge implementation, which exposes mutable proxies for host-realm intrinsic prototypes, and forwards sandbox writes into the underlying host objects. The vulnerability, identified as CVE-2026-44005, poses a significant risk to applications relying on vm2 for secure code execution, as it can lead to arbitrary code execution in the host environment.

## Attack Chain

1. Attacker provides malicious JavaScript code to the vm2 sandbox environment.
2. The malicious code uses `__lookupGetter__` to access the `__proto__` property of a sandboxed object.
3. The `BaseHandler.get()` function in `lib/bridge.js` returns the host-side descriptor or proxy target prototype for `__proto__`.
4. The attacker abuses the host `__lookupGetter__('__proto__')` accessor repeatedly, walking up the prototype chain.
5. This walk eventually leads to a proxy of a host intrinsic prototype, such as `Object.prototype`, `Array.prototype`, or `Function.prototype`.
6. The malicious code uses `BaseHandler.set()` or `BaseHandler.defineProperty()` to write attacker-controlled data into the host intrinsic prototype.
7. `otherReflectSet` or `otherReflectDefineProperty` then propagates the changes to the host environment, bypassing the sandbox.
8. Successful prototype pollution allows the attacker to execute arbitrary code in the host environment, escaping the vm2 sandbox.

## Impact

Successful exploitation of this vulnerability allows an attacker to escape the vm2 sandbox and pollute the prototypes of core JavaScript objects in the host environment. This can lead to a variety of consequences, including arbitrary code execution in the host process. This vulnerability affects applications using vm2 versions 3.9.6 through 3.10.5, potentially impacting a wide range of systems that rely on sandboxed JavaScript execution. The prototype pollution can compromise the integrity and security of the host application.

## Recommendation

*   Upgrade to a patched version of vm2 that addresses CVE-2026-44005.
*   Monitor for attempts to access `__proto__` via `__lookupGetter__` within vm2 sandboxes using the `Detect VM2 Prototype Access` Sigma rule.
*   Implement additional input validation and sanitization to prevent malicious JavaScript code from being executed in the vm2 sandbox.
*   Consider alternative sandboxing solutions or code review practices to mitigate the risk of sandbox escape vulnerabilities.
