---
title: vm2 Sandbox Escape Vulnerability Leading to RCE
slug: 2024-01-vm2-sandbox-escape
description: A sandbox escape vulnerability exists in the vm2 npm package, specifically in versions 3.10.5 and earlier, allowing an attacker to reach BaseHandler.getPrototypeOf via util.inspect, potentially leading to arbitrary prototype access and remote code execution (RCE).
date: "2026-05-07T03:54:34Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sandbox-escape
  - rce
  - vm2
  - javascript
vendors:
  - npm
products:
  - vm2 (<= 3.10.5)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: JavaScript'
references:
  - https://github.com/advisories/GHSA-qcp4-v2jj-fjx8
rules:
  - title: Detect vm2 Sandbox Escape - Suspicious util.inspect Usage
    description: Detects suspicious usage of util.inspect with showHidden and showProxy options, which is indicative of attempts to exploit the vm2 sandbox escape vulnerability.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect vm2 Sandbox Escape - child_process.execSync in WebAssembly
    description: Detects the execution of child_process.execSync within a WebAssembly module, which is a strong indicator of a sandbox escape attempt in vm2.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The vm2 npm package, a sandbox for executing untrusted JavaScript code, is vulnerable to a sandbox escape that can lead to remote code execution (RCE). This vulnerability, affecting versions 3.10.5 and earlier, stems from the ability to reach `BaseHandler.getPrototypeOf` through manipulation of `util.inspect`. By exploiting this flaw, an attacker can gain access to arbitrary prototypes within the vm2 sandbox, bypassing security restrictions and ultimately executing arbitrary code on the host system. The vulnerability was reported on May 7, 2026, and poses a significant risk to applications relying on vm2 for secure JavaScript execution. Successful exploitation allows attackers to break out of the sandbox environment and compromise the underlying system.

## Attack Chain

1.  The attacker crafts a malicious JavaScript payload designed to exploit the `util.inspect` function within the vm2 sandbox.
2.  The payload leverages the `subarray` and `slice` properties of the `Buffer.prototype` to trigger the `inspect` function.
3.  The `showHidden` and `showProxy` options are enabled in `util.inspect` to expose internal properties and proxies.
4.  Within the `stylize` function, the attacker gains access to the `BaseHandler.getPrototypeOf` method.
5.  Using `getPrototypeOf`, the attacker retrieves the prototype of the `Buffer` object multiple times to reach the `HObjectProto` and subsequently its constructor `HObject`.
6.  The attacker retrieves a symbol from the `Buffer.prototype` using `HObject.getOwnPropertySymbols`.
7.  A new object is created with the retrieved symbol as a key, whose value is a function that retrieves the `child_process` module.
8.  Finally, the attacker uses `child_process.execSync` to execute arbitrary commands on the host system, escaping the vm2 sandbox and achieving RCE.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass the vm2 sandbox and execute arbitrary commands on the host system. This can lead to complete system compromise, including data theft, malware installation, and denial of service. The vulnerability affects any application using vm2 versions 3.10.5 or earlier, potentially impacting a wide range of projects that rely on secure JavaScript execution. Given the severity (critical) and the potential for RCE, immediate action is required to mitigate this risk.

## Recommendation

*   Upgrade the `vm2` npm package to a version greater than 3.10.5 to patch the vulnerability (CVE-2026-44006).
*   Monitor application logs for suspicious activity related to `util.inspect` and `Buffer` manipulation, which may indicate exploitation attempts.
*   Implement strict input validation and sanitization to prevent attackers from injecting malicious JavaScript code into the vm2 sandbox.
