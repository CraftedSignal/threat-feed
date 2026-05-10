---
title: VM2 Sandbox Breakout via neutralizeArraySpeciesBatch Method
slug: 2024-01-vm2-sandbox-breakout
description: A sandbox breakout vulnerability in vm2 allows attackers to execute arbitrary commands on the host system by exploiting the `neutralizeArraySpeciesBatch` method to access host objects and the Function object.
date: "2024-01-03T17:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sandbox-escape
  - rce
  - javascript
products:
  - vm2 (<= 3.11.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1203
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-9qj6-qjgg-37qq
rules:
  - title: Detect VM2 Sandbox Escape via Array Prototype Manipulation
    description: Detects manipulation of the Array prototype within a vm2 context, which is indicative of a sandbox escape attempt (CVE-2026-44008).
    platform: sigma
    severity: critical
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1203
    data_sources:
      - process_creation
      - linux
  - title: Detect Host Command Execution from VM2 Sandbox
    description: Detects execution of commands on the host system originating from a vm2 sandbox, indicating a successful sandbox escape (CVE-2026-44008).
    platform: sigma
    severity: critical
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1203
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical sandbox escape vulnerability has been identified in vm2 versions 3.11.1 and earlier. This flaw allows an attacker to bypass the intended security restrictions of the vm2 sandbox, gaining the ability to execute arbitrary code on the host system. The vulnerability stems from the `neutralizeArraySpeciesBatch` method, which improperly handles objects from different contexts. By exploiting this, an attacker can gain access to host objects, including the host `Function` object, effectively breaking out of the sandbox. This poses a significant risk to applications relying on vm2 for secure code execution, as it could lead to complete system compromise.

## Attack Chain

1.  The attacker injects malicious JavaScript code into the vm2 sandbox.
2.  The injected code manipulates the `Array.prototype` using `Object.defineProperty`.
3.  The `neutralizeArraySpeciesBatch` method is triggered, which attempts to neutralize objects passed between the sandbox and the host.
4.  The code leverages a getter on the array prototype to expose objects from the host environment into the sandbox.
5.  The attacker obtains a reference to the host's `Buffer.prototype.inspect` function through the exposed objects.
6.  The attacker uses `Buffer.prototype.inspect.constructor.constructor` to obtain a reference to the host's `Function` constructor.
7.  The `Function` constructor is then used to execute arbitrary code on the host system, such as using `child_process.execSync` to create a file.
8.  The attacker achieves remote code execution on the host, bypassing the vm2 sandbox.

## Impact

Successful exploitation of this vulnerability allows attackers to execute arbitrary commands on the host system. This can lead to complete system compromise, data exfiltration, or denial-of-service. Given the widespread use of vm2 in sandboxing JavaScript code, a successful attack could have significant consequences for many applications and systems. The vulnerability has been assigned CVE-2026-44008 and is rated as critical severity.

## Recommendation

*   Upgrade to a patched version of vm2 (later than 3.11.1) to remediate CVE-2026-44008.
*   Deploy the Sigma rule "Detect VM2 Sandbox Escape via Array Prototype Manipulation" to identify exploitation attempts within your environment.
*   Enable process creation logging to allow for detection of commands executed by the escaped sandbox, as identified by the Sigma rule "Detect Host Command Execution from VM2 Sandbox".
