---
title: VM2 Sandbox Escape Vulnerability via SuppressedError
slug: 2024-01-vm2-sandbox-escape
description: A sandbox escape vulnerability exists in vm2 version 3.10.4 running on Node.js v24.13.0, leveraging `SuppressedError` to allow attackers to execute arbitrary code on the host system.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sandbox-escape
  - code-execution
  - vm2
vendors:
  - npm
products:
  - vm2 (<= 3.10.4)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
cves:
  - id: CVE-2026-26332
    cvss: 9.8
references:
  - https://github.com/advisories/GHSA-55hx-c926-fr95
rules:
  - title: Detect Suspicious Node.js Child Processes
    description: Detects suspicious child processes spawned by Node.js, potentially indicating a sandbox escape or code execution vulnerability.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect Shell Commands Executed via Node.js Child Processes
    description: Detects shell commands executed via Node.js child processes, potentially indicating malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A critical sandbox escape vulnerability, CVE-2026-26332, has been identified in vm2 version 3.10.4 when used with Node.js v24.13.0. The vulnerability stems from improper handling of `SuppressedError` objects within the vm2 sandbox environment. An attacker can exploit this flaw to bypass the sandbox restrictions and execute arbitrary code on the host system. This can lead to complete compromise of the host machine if untrusted code is executed within the vulnerable vm2 sandbox. The proof-of-concept exploit demonstrates the ability to execute shell commands, highlighting the severity of the vulnerability. Defenders should prioritize patching or mitigating this vulnerability to prevent potential system compromise.

## Attack Chain

1.  The attacker provides malicious JavaScript code to the vm2 sandbox.
2.  The code creates a `DisposableStack` object to trigger the vulnerability.
3.  The `defer` method of `DisposableStack` is used to schedule functions that throw errors.
4.  An error object is created with its `name` property set to a Symbol, manipulating error handling.
5.  The `dispose` method of `DisposableStack` is called within a try-catch block.
6.  The `SuppressedError` object is caught in the catch block.
7.  The attacker accesses the constructor of the suppressed error, obtaining a Function constructor.
8.  The attacker uses the Function constructor to access the `process` object and execute arbitrary commands on the host system using `node:child_process`.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code on the host system. This can lead to complete system compromise, including data theft, installation of malware, and denial-of-service. The vulnerability affects any application using vm2 to sandbox untrusted JavaScript code. The specific number of affected applications is unknown, but the widespread use of vm2 makes this a significant threat.

## Recommendation

*   Upgrade to a patched version of `vm2` that addresses CVE-2026-26332.
*   Monitor process creation events for suspicious child processes spawned by Node.js using the "Detect Suspicious Node.js Child Processes" Sigma rule.
*   Consider implementing input validation and sanitization on code submitted to the vm2 sandbox to prevent the injection of malicious payloads.
