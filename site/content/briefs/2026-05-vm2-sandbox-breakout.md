---
title: VM2 Sandbox Breakout via Async Generator
slug: 2026-05-vm2-sandbox-breakout
description: A sandbox breakout vulnerability exists in vm2, tracked as CVE-2026-45411, allowing attackers to execute arbitrary commands on the host system by manipulating async generators to catch host exceptions, leading to remote code execution.
date: "2026-05-14T21:16:46Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:vm2_project:vm2:*:*:*:*:*:node.js:*:*
tags:
  - sandbox-escape
  - rce
  - vm2
vendors:
  - NPM
products:
  - vm2 (<= 3.11.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1202
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-45411
    cvss: 9.8
    epss: 0.00054
references:
  - https://github.com/advisories/GHSA-248r-7h7q-cr24
  - CVE-2026-45411
rules:
  - title: Detect VM2 Sandbox Breakout via Async Generator
    description: Detects CVE-2026-45411 exploitation — Attempts to exploit VM2 sandbox breakout using async generators and exception handling to execute arbitrary code on the host system.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

A critical sandbox breakout vulnerability has been identified in vm2, a popular Node.js sandbox environment. This flaw, identified as CVE-2026-45411, allows malicious code to escape the confines of the vm2 sandbox and execute arbitrary commands on the host system. The vulnerability stems from the improper handling of exceptions within async generators, specifically when using the `yield*` expression. This allows attackers to catch host exceptions and manipulate the execution flow to achieve code execution outside the sandbox. The affected versions are vm2 versions 3.11.2 and earlier. This vulnerability poses a significant risk to applications relying on vm2 for secure code execution, potentially leading to complete system compromise.

## Attack Chain

1. The attacker provides malicious JavaScript code to the vm2 sandbox.
2. The malicious code defines an async generator function that utilizes the `yield*` expression.
3. The code triggers a host exception within the sandbox environment.
4. The exception is caught within the async generator using a specially crafted iterator.
5. The attacker manipulates the caught exception object to access host objects and functions.
6. This access is used to bypass the sandbox restrictions.
7. The attacker gains access to the `child_process` module.
8. The attacker executes arbitrary commands on the host system using `child_process.execSync()`.

## Impact

Successful exploitation of this vulnerability allows attackers to perform Remote Code Execution (RCE) on the host system. This can lead to a complete compromise of the affected system, including data theft, system corruption, and further propagation of malicious activity. Given the popularity of vm2 in sandboxing untrusted JavaScript code, a wide range of applications and systems could be at risk if they are using versions 3.11.2 or earlier.

## Recommendation

*   Upgrade to vm2 version 3.11.3 or later to patch CVE-2026-45411.
*   Deploy the Sigma rule "Detect VM2 Sandbox Breakout via Async Generator" to your SIEM to detect potential exploitation attempts.
*   Implement strict input validation and sanitization to minimize the risk of malicious code being introduced into the vm2 sandbox.
