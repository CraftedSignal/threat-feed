---
title: SandboxJS Function.caller Sandbox Escape Vulnerability (CVE-2026-43898)
slug: 2026-05-sandboxjs-escape
description: SandboxJS is vulnerable to a sandbox escape (CVE-2026-43898); by exploiting the `Function.caller` property, sandboxed code can access the internal `LispType.Call` runtime callback, which allows an attacker to manipulate the context and arguments of the callback, leading to the execution of arbitrary host JavaScript and a complete sandbox escape.
date: "2026-05-11T19:42:07Z"
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
  - nyariv
products:
  - '@nyariv/sandboxjs (<= 0.9.5)'
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-g8f2-4f4f-5jqw
rules:
  - title: Detect SandboxJS Function Caller Abuse
    description: Detects attempts to exploit the SandboxJS Function.caller vulnerability (CVE-2026-43898) by identifying calls to Function.caller within a sandboxed environment.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect SandboxJS Arbitrary Code Execution
    description: Detects CVE-2026-43898 exploitation - Identifies process execution resulting from SandboxJS RCE by monitoring for unexpected child processes spawned from node processes running SandboxJS.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

SandboxJS is a JavaScript sandbox environment that allows the execution of untrusted code in a controlled manner. A critical vulnerability, CVE-2026-43898, exists in versions 0.9.5 and earlier. This vulnerability allows a malicious actor to escape the sandbox and execute arbitrary JavaScript code on the host system. The vulnerability stems from the exposure of the `Function.caller` property within the sandbox. By exploiting this property, sandboxed code can gain access to the internal `LispType.Call` runtime callback, enabling manipulation of the callback's context and arguments to execute arbitrary commands. This vulnerability poses a significant risk, potentially leading to remote code execution (RCE) on systems utilizing the vulnerable SandboxJS package.

## Attack Chain

1.  The attacker injects malicious JavaScript code into the SandboxJS environment.
2.  The injected code uses `Function.caller` to obtain a reference to the internal `LispType.Call` runtime callback.
3.  The attacker crafts a fake `context` and `obj` to pass as arguments to the leaked callback.
4.  The crafted context includes a `capture` function that intercepts the internal function call within SandboxJS.
5.  The attacker uses the captured function to leak static properties of the `Object` constructor.
6.  The attacker obtains a reference to the host `Function` constructor by calling internal primitive functions.
7.  The attacker crafts a string containing JavaScript code to execute on the host system.
8.  The attacker invokes the host `Function` constructor with the malicious JavaScript code, resulting in remote code execution on the host.

## Impact

Successful exploitation of this vulnerability (CVE-2026-43898) allows an attacker to bypass the SandboxJS sandbox and execute arbitrary JavaScript code on the host system. This can lead to complete system compromise, including data theft, malware installation, and denial-of-service. Given the nature of sandboxes being used to execute untrusted code, the impact is typically critical. The vulnerability affects all users of `@nyariv/sandboxjs` versions 0.9.5 and earlier.

## Recommendation

*   Upgrade the `@nyariv/sandboxjs` package to a version greater than 0.9.5 to patch CVE-2026-43898.
*   Deploy the Sigma rule "Detect SandboxJS Function Caller Abuse" to detect attempts to exploit the `Function.caller` vulnerability.
*   Monitor JavaScript execution within SandboxJS environments for unexpected calls to `Function.caller`.
