---
title: VM2 Sandbox Escape via JSPI Promise .finally() Species Bypass (CVE-2026-47210)
slug: 2026-05-vm2-sandbox-escape
description: A sandbox escape vulnerability, CVE-2026-47210, in `vm2` allows arbitrary code execution in the host process when untrusted code is executed with async support on runtimes exposing WebAssembly JSPI, bypassing Promise-species hardening and exposing a host-originated rejection object to attacker-controlled species logic.
date: "2026-05-29T17:51:55Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sandbox-escape
  - rce
  - vm2
vendors:
  - npm
products:
  - vm2 (<= 3.11.3)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
references:
  - https://github.com/advisories/GHSA-6j2x-vhqr-qr7q
  - CVE-2026-47210
rules:
  - title: Detect Suspicious Child Process from Node.js
    description: Detects unusual child processes spawned from Node.js processes, potentially indicating command execution after a vm2 sandbox escape.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect vm2 WebAssembly Promise .finally()
    description: Detects vm2 activity involving WebAssembly, Promises, and the .finally() method, indicating potential exploitation of CVE-2026-47210.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A critical sandbox escape vulnerability exists in `vm2` (versions 3.11.3 and earlier) that allows for arbitrary code execution on the host system. This vulnerability, assigned CVE-2026-47210, occurs when `vm2` is used with Node.js runtimes (specifically Node 26) that expose WebAssembly JSPI features (`WebAssembly.promising` / `WebAssembly.Suspending`). By exploiting the interaction between JSPI-backed Promises and the `.finally()` method, an attacker can bypass the intended sandbox protection and gain access to the host process. This bypass exposes a host-originated TypeError during JSPI processing which exposes a usable host constructor chain within attacker-controlled species logic. This can lead to full compromise of services relying on `vm2` isolation.

## Attack Chain

1.  Attacker provides untrusted JavaScript code to the `vm2` sandbox environment.
2.  The JavaScript code leverages WebAssembly JSPI features, specifically `WebAssembly.promising` and `WebAssembly.Suspending`, to create JSPI-backed Promises.
3.  The attacker manipulates the JSPI-backed Promise to reach the `Promise.prototype.finally()` method.
4.  The `finally()` method is triggered, leading to execution of attacker-controlled species logic.
5.  A host-originated `TypeError` is generated during JSPI processing due to the Promise rejection.
6.  The rejection object from the TypeError exposes a host constructor chain to the attacker.
7.  The attacker utilizes the host constructor chain to gain access to the host `process` object.
8.  The attacker leverages the `process` object (e.g., `process.mainModule.require('child_process').execSync`) to execute arbitrary commands on the host system, escaping the sandbox.

## Impact

This vulnerability allows for a complete sandbox escape, leading to arbitrary code execution in the host process. This poses a significant risk to applications relying on `vm2` for security isolation. Successful exploitation can result in arbitrary command execution, unauthorized file access (read/write), theft of sensitive data (secrets, tokens, credentials), and full compromise of services utilizing `vm2`. This issue affects applications using `vm2` to execute untrusted JavaScript, especially those running on Node.js 26.

## Recommendation

*   Upgrade `vm2` to a version greater than 3.11.3 to patch CVE-2026-47210.
*   Apply the following rules to detect potential exploitation attempts targeting `vm2` sandboxes.
*   Monitor process creation events for unexpected child processes spawned from Node.js processes, especially if they involve command execution (Rule: "Detect Suspicious Child Process from Node.js").
*   Monitor `vm2` for suspicious activity related to WebAssembly and Promise handling (Rule: "Detect vm2 WebAssembly Promise .finally()").
