---
title: Sandbox Escape in vm2 via NodeVM Configuration Misvalidation
slug: 2026-09-vm2-sandbox-escape
description: An improper validation of the 'require' configuration in the vm2 Node.js sandbox allows attackers to bypass nesting restrictions and achieve arbitrary code execution by spawning an inner NodeVM with elevated privileges.
date: "2026-09-17T15:57:37Z"
lastmod: "2026-09-17T17:58:21Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:vm2_project:vm2:*:*:*:*:*:node.js:*:*
tags:
  - sandbox-escape
  - nodejs
  - code-execution
  - vulnerability
  - vm2
  - rce
  - javascript
  - cve
products:
  - vm2 (>= 3.11.4 and <= 3.11.6)
  - vm2 (3.11.6)
  - vm2 (3.11.3-3.11.6)
  - vm2 (3.11.3 - 3.11.6)
  - vm2 (3.10.2 - 3.11.6)
  - vm2 (< 3.11.7)
  - vm2 (>= 3.9.6, <= 3.11.6)
  - vm2 (3.11.0-3.11.7)
  - vm2 (3.10.1 - 3.11.6)
  - vm2 (<= 3.11.6)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker... can execute arbitrary commands with the privileges of the host Node.js process, escaping the sandbox.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.006
    technique_name: JavaScript
    evidence: An attacker within the sandbox can then utilize these leaked host objects to access 'child_process' or other privileged modules, resulting in arbitrary code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Sandboxed code can create an in-memory DatabaseSync with extension loading enabled and call DatabaseSync.loadExtension() on a native library.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: SQLite loads the library into the Node.js host process and invokes its native entry point, giving the sandboxed plugin arbitrary native code execution.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
    evidence: The builtin loader wraps host modules in a read-only proxy, but method calls such as Agent.prototype.on() are forwarded to the underlying host object, so sandbox code can register a listener for the agent's 'free' event.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: JavaScript'
    evidence: Attackers can use prototype-walking primitives to reach and modify host Uint8Array.prototype, %TypedArray%.prototype, and ArrayBuffer.prototype.
    confidence_band: high
cves:
  - id: CVE-2026-92935
    cvss: 9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92935
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92937
  - https://github.com/advisories/GHSA-m283-3h24-438v
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92938
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92940
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92941
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92944
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92946
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92948
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92953
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92956
  - https://github.com/advisories/GHSA-6j2x-vhqr-qr7q
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92957
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92942
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92951
action_plan:
  priority: elevated
  owners:
    - Development
    - AppSec
  immediate_actions:
    - action: Upgrade all instances of vm2 to version 3.11.7.
      owner: Development
      due: 48h
      evidence: This issue is fixed in vm2 3.11.7.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to vm2 3.11.7.
      owner: IT Operations
      addresses: CVE-2026-92935
      evidence: NVD vulnerability disclosure.
updates:
  - at: "2026-09-17T15:58:50Z"
    level: L2
    summary: added coverage for vm2 (3.11.0-3.11.7)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-92953
  - at: "2026-09-17T15:58:57Z"
    level: L2
    summary: added coverage for vm2 (3.10.1 - 3.11.6)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-92956
  - at: "2026-09-17T15:59:04Z"
    level: L2
    summary: added coverage for vm2 (<= 3.11.6)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-92957
  - at: "2026-09-17T15:59:18Z"
    level: L1
    summary: added coverage for vm2 (<= 3.11.6)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-92942
  - at: "2026-09-17T17:58:21Z"
    level: L2
    summary: added coverage for vm2 (< 3.11.7)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-92951
---

The vm2 library, commonly used as a sandbox for executing untrusted Node.js code, contains a critical vulnerability (CVE-2026-92935) in its NodeVM constructor logic. In versions 3.11.4 through 3.11.6, the `hasRealRequireConfig` check fails to correctly validate the `require` option when provided as an array. Specifically, passing an array-shaped `require` object satisfies the guard meant to reject nesting without explicit configuration. 

This logic flaw allows an attacker to manipulate the `makeResolverFromLegacyOptions()` function, leading to the creation of a resolver that exposes the host's `vm2` module. By supplying a payload that initiates a `NodeVM` with `nesting: true` and a malicious `require` array, an attacker can escape the sandbox boundaries. Once escaped, the attacker can create an inner `NodeVM` with arbitrary builtin privileges, such as `child_process`, enabling the execution of arbitrary commands under the context of the host Node.js process. This vulnerability is addressed in vm2 version 3.11.7.

## Impact

Successful exploitation allows for full sandbox escape and arbitrary code execution within the host environment. This impacts any application relying on vm2 for isolation of untrusted JavaScript, potentially leading to unauthorized data access, system-level command execution, and full compromise of the Node.js application process.

## Recommendation

- Upgrade the vm2 dependency to version 3.11.7 or later across all applications utilizing this library to mitigate CVE-2026-92935.
- Audit all application code utilizing the `NodeVM` constructor to ensure the `require` configuration is strictly defined as an object rather than an array.
- Implement process-level sandboxing (e.g., containers, gVisor) as a secondary defense layer to limit the impact of a potential sandbox escape.
