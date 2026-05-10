---
title: vm2 Sandbox Breakout via Null Proto Exception (CVE-2026-44009)
slug: 2026-05-vm2-sandbox-breakout
description: A sandbox breakout vulnerability exists in vm2 that allows attackers to execute arbitrary commands on the host system by exploiting a null proto exception in `handleException` to obtain proxied and unproxied objects, leading to the retrieval of the host `Function` object and subsequent remote code execution.
date: "2026-05-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sandbox-escape
  - rce
  - vm2
products:
  - vm2 (< 3.11.2)
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
  - https://github.com/advisories/GHSA-9vg3-4rfj-wgcm
rules:
  - title: Detect vm2 Sandbox Breakout Attempt via Null Proto Exception
    description: Detects CVE-2026-44009 exploitation — Attempts to create objects with null prototypes and throw them as exceptions within vm2 to escape the sandbox.
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
  - title: Detect vm2 Sandbox Breakout - Suspicious child_process.execSync
    description: Detects potential vm2 sandbox breakout by monitoring for the use of child_process.execSync which is often used to execute code on the host system
    platform: sigma
    severity: high
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

A critical sandbox breakout vulnerability has been discovered in vm2, a popular Node.js sandbox environment. This flaw, identified as CVE-2026-44009, allows malicious actors to bypass the intended security restrictions and execute arbitrary code on the host system. The vulnerability stems from an error in the `handleException` function related to exceptions with a null prototype. Attackers can craft specific code within the vm2 sandbox that leverages this error to gain access to the host's `Function` object, ultimately leading to remote code execution. This vulnerability impacts vm2 versions prior to 3.11.2. Successful exploitation enables attackers to perform unauthorized actions on the underlying system, potentially compromising sensitive data or system integrity.

## Attack Chain

1.  Attacker crafts malicious JavaScript code designed to exploit the null proto exception within the vm2 sandbox.
2.  The malicious code defines an object with a null prototype (`__proto__: null`).
3.  The code attempts to throw the null proto object as an exception within the vm2 environment.
4.  The `handleException` function incorrectly assumes that the exception originates from outside the sandbox due to the null proto.
5.  This leads to the creation of both proxied and unproxied versions of the sandbox object.
6.  The attacker manipulates the proxied and unproxied objects to access the `Buffer.prototype.inspect` function.
7.  Using the `constructor` property of the function, the attacker gains access to the host's `Function` object.
8.  The attacker uses the host `Function` object to execute arbitrary commands on the host system, such as creating a file named 'pwned'.

## Impact

Successful exploitation of this vulnerability (CVE-2026-44009) allows an attacker to bypass the vm2 sandbox and execute arbitrary code on the host system. This can lead to complete system compromise, including data theft, malware installation, and denial-of-service attacks. The vulnerability affects any application that relies on vm2 for secure code execution, potentially impacting a wide range of Node.js-based applications and services. The impact is significant due to the ease of exploitation and the potential for complete system takeover.

## Recommendation

*   Upgrade to vm2 version 3.11.2 or later to patch CVE-2026-44009.
*   Implement the Sigma rule "Detect vm2 Sandbox Breakout Attempt via Null Proto Exception" to detect exploitation attempts by monitoring for the specific code patterns used in the proof-of-concept.
*   Continuously monitor vm2 environments for suspicious activity, including unexpected process creation or file system modifications, which may indicate a successful sandbox escape.
