---
title: VM2 Sandbox Escape via __lookupGetter__ Vulnerability
slug: 2024-01-vm2-sandbox-breakout
description: VM2 is vulnerable to a sandbox breakout via the `__lookupGetter__` method, enabling attackers to execute arbitrary commands on the host system by exploiting context switching and property descriptor manipulation, leading to remote code execution.
date: "2024-01-03T12:00:00Z"
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
  - vm2 (<= 3.10.4)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: JavaScript'
references:
  - https://github.com/advisories/GHSA-grj5-jjm8-h35p
rules:
  - title: Detect Node.js Child Process Execution
    description: Detects the use of child_process.execSync within a Node.js environment, which could indicate a sandbox escape attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1566
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious __lookupGetter__ Use in Process Creation
    description: Detects process creation events where the command line contains `__lookupGetter__`, which is often used in exploits targeting JavaScript sandboxes such as vm2.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1611
    data_sources:
      - process_creation
      - linux
  - title: nodejs_child_process_exec
    description: Detects the use of child_process.execSync within a Node.js environment, indicating potential command execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

The vm2 library, a popular Node.js sandbox environment, is susceptible to a critical sandbox breakout vulnerability. This flaw allows malicious code executed within the vm2 sandbox to escape its confines and execute arbitrary commands on the host operating system. The vulnerability leverages the `__lookupGetter__` method to bypass context isolation and gain access to host-level functions and objects. Previous attempts to mitigate similar issues were circumvented using `Object.getOwnPropertyDescriptor` to access the constructor property. The vulnerability affects vm2 versions 3.10.4 and earlier. Exploitation allows an attacker to achieve remote code execution with the privileges of the Node.js process running the vm2 sandbox, which could lead to significant system compromise.

## Attack Chain

1.  Attacker injects malicious JavaScript code into the vm2 sandbox.
2.  The injected code retrieves the `__lookupGetter__` method, which is used to access the getter of an object.
3.  The malicious code obtains the `apply` method from the `Buffer` object within the sandbox.
4.  The `apply` method is used to invoke the host version of `__lookupGetter__` with `Buffer` and `__proto__` as arguments, gaining access to the host's prototype lookup method.
5.  The host's `Function.prototype` object is retrieved using the prototype lookup method.
6.  The `constructor` property of the `Function.prototype` object is accessed using `Object.getOwnPropertyDescriptor` to bypass previous mitigation attempts.
7.  The host `Function` constructor is used to create a new function that returns the `process` object, granting access to Node.js runtime functions on the host.
8.  The code then uses `child_process.execSync` to execute arbitrary commands on the host system (e.g., `touch pwned`).

## Impact

Successful exploitation of this vulnerability allows attackers to execute arbitrary code on the host system. Given the critical nature of many applications that employ sandboxing, this can lead to complete system compromise, data exfiltration, and denial of service. The vulnerability affects vm2 versions up to and including 3.10.4. The impact includes remote code execution, potentially leading to sensitive data exposure, system takeover, or further lateral movement within a network.

## Recommendation

*   Upgrade to a patched version of vm2 greater than 3.10.4 to remediate CVE-2026-24118.
*   Implement strict input validation and sanitization to minimize the risk of malicious code injection into the vm2 sandbox.
*   Monitor process creation events on the host system for suspicious activity originating from Node.js processes, which may indicate a sandbox escape (see the process_creation Sigma rule below).
*   Monitor for the execution of commands such as `child_process.execSync` called from within vm2 sandboxes to detect potential exploitation attempts (see the `nodejs_child_process_exec` Sigma rule).
