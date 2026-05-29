---
title: vm2 Sandbox Escape Vulnerability (CVE-2026-47131)
slug: 2026-05-vm2-sandbox-escape
description: A sandbox escape vulnerability exists in vm2 versions 3.11.3 and earlier, allowing attackers to execute arbitrary code on the host system by manipulating the prototype chain and exploiting Node.js error handling.
date: "2026-05-29T17:34:43Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sandbox-escape
  - rce
  - javascript
vendors:
  - vm2
products:
  - vm2 (<= 3.11.3)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1202
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-v6mx-mf47-r5wg
  - CVE-2026-47131
rules:
  - title: Detect vm2 Sandbox Escape - Process Creation
    description: Detects CVE-2026-47131 exploitation — creation of suspicious processes by node.js after sandbox escape
    platform: sigma
    severity: critical
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect vm2 Sandbox Escape - WASM CompileStreaming Error
    description: Detects CVE-2026-47131 exploitation — WASM compile streaming error followed by prototype manipulation attempts in node.js
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical sandbox escape vulnerability, tracked as CVE-2026-47131, has been identified in vm2, a popular Node.js sandbox environment. This flaw allows malicious code executed within the vm2 sandbox to break out and execute arbitrary commands on the host system. The vulnerability stems from the ability to manipulate JavaScript prototypes within the sandbox, specifically targeting the `Buffer` object and Node.js's error handling mechanisms. The exploit leverages the combination of `Buffer.call.call({}.__lookupGetter__, Buffer, "__proto__")`, `Buffer.call.call({}.__lookupSetter__, Buffer, "__proto__")`, and the `ERR_INVALID_ARG_TYPE` error to gain access to the host's `TypeError` constructor, ultimately leading to code execution outside the sandbox. This vulnerability impacts vm2 versions 3.11.3 and earlier.

## Attack Chain

1.  The attacker injects malicious JavaScript code into the vm2 sandbox.
2.  The injected code uses `Buffer.call.call({}.__lookupGetter__, Buffer, "__proto__")` to obtain the prototype getter of the `Buffer` object.
3.  The injected code uses `Buffer.call.call({}.__lookupSetter__, Buffer, "__proto__")` to obtain the prototype setter of the `Buffer` object.
4.  The code triggers a `TypeError` by attempting an invalid WebAssembly compilation via `WebAssembly.compileStreaming()`.
5.  The prototype of the `TypeError` object is then manipulated using the previously obtained getter and setter methods.
6.  A second attempt to compile invalid WebAssembly triggers another `TypeError`.
7.  The constructor of this second `TypeError` is used to access the `HostFunction` constructor.
8.  The `HostFunction` constructor is used to create a function that returns the `process` object, which is then used to execute arbitrary commands on the host system, bypassing the sandbox.

## Impact

Successful exploitation of this vulnerability allows attackers to execute arbitrary code on the host system running the vm2 sandbox. This could lead to complete system compromise, data theft, or denial of service. Given the widespread use of vm2 in various applications, including CI/CD pipelines and online code execution environments, this vulnerability poses a significant risk. The vulnerability affects all users of vm2 versions 3.11.3 and earlier.

## Recommendation

*   Upgrade vm2 to a version greater than 3.11.3 to patch CVE-2026-47131.
*   Monitor for suspicious process creation events originating from Node.js processes to detect potential exploitation attempts using the Sigma rule "Detect vm2 Sandbox Escape - Process Creation".
*   Implement strict input validation and sanitization to prevent the injection of malicious JavaScript code into the vm2 sandbox.
*   Review and restrict the use of `WebAssembly.compileStreaming()` to prevent abuse, as demonstrated in the PoC.
