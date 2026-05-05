---
title: VM2 Sandbox Escape Vulnerability (CVE-2026-26956)
slug: 2024-01-03-vm2-sandbox-escape
description: A critical vulnerability, CVE-2026-26956, exists in vm2 version 3.10.4 when running on Node.js v25.6.1 (x64 Linux), allowing a full sandbox escape with arbitrary code execution through attacker-controlled code passed to `VM.run()`.
date: "2026-05-05T16:44:16Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sandbox-escape
  - wasm
  - vm2
  - javascript
vendors:
  - vm2
products:
  - vm2 (= 3.10.4)
  - Node.js
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-26956
    cvss: 9.8
references:
  - https://github.com/advisories/GHSA-ffh4-j6h5-pg66
rules:
  - title: Detect Suspicious Node.js Child Processes
    description: Detects suspicious child processes spawned by Node.js, which could indicate a sandbox escape.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect WebAssembly with JSTag
    description: Detects the usage of WebAssembly with JSTag functionality, used in vm2 escape.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical vulnerability, CVE-2026-26956, has been identified in vm2 version 3.10.4 when used with Node.js v25.6.1 (x64 Linux). This vulnerability allows for a complete sandbox escape, granting attackers the ability to execute arbitrary code on the host system. The attack is triggered by supplying malicious code to the `VM.run()` function. This vulnerability bypasses vm2's intended security mechanisms, exploiting weaknesses in WebAssembly exception handling and JSTag support within the Node.js environment. The root cause lies in the insufficient sanitization of TypeError exceptions originating from Symbol-to-string coercion during stack formatting within WebAssembly's `try_table` instruction. This flaw allows attacker code to gain access to the host process object and execute system commands without any cooperation from the host environment.

## Attack Chain

1. Attacker crafts malicious JavaScript code containing a WebAssembly module.
2. The attacker's code is passed as an argument to the `VM.run()` function within the vm2 sandbox.
3. The WebAssembly module is instantiated, containing a function that triggers a TypeError by attempting Symbol-to-string coercion during stack formatting (e.g., `e.name = Symbol(); e.stack`).
4. The `try_table` instruction in WebAssembly catches the JavaScript exception at the V8 C++ level as an opaque `externref`.
5. This exception is improperly sanitized by vm2 and returned to the attacker's code as a function return value.
6. The attacker leverages the unsanitized TypeError object to access its constructor chain (`hostError.constructor.constructor`).
7. The constructor chain resolves to a Function object that, when called, returns the host process object.
8. The attacker uses the host process object to require modules like `child_process` and `console`, enabling arbitrary code execution on the host system.

## Impact

Successful exploitation of this vulnerability allows an attacker to completely bypass the vm2 sandbox and execute arbitrary code on the host system with the privileges of the Node.js process. This can lead to complete system compromise, data exfiltration, and other malicious activities. Given the criticality of many applications relying on sandboxed environments, this vulnerability poses a significant risk to affected systems. Observed successful exploitation allowed for privilege escalation to root.

## Recommendation

*   Upgrade to a patched version of vm2 that addresses CVE-2026-26956 if available from the vendor.
*   As a temporary mitigation, consider disabling WebAssembly exception handling or JSTag support in Node.js v25.6.1.
*   Monitor process creation events for suspicious child processes spawned from Node.js processes, as detected by the rule "Detect Suspicious Node.js Child Processes".
*   Deploy the Sigma rule "Detect WebAssembly with JSTag" to identify the use of WebAssembly with JSTag functionality, which is a prerequisite for exploiting this vulnerability.
