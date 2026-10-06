---
title: Critical Sandbox Escape Vulnerability in vm2
slug: 2026-10-vm2-sandbox-escape
description: The vm2 JavaScript sandbox environment contains a critical vulnerability (CVE-2026-92955) allowing attackers to escape the sandbox via prototype chain manipulation and execute arbitrary code on the host system.
date: "2026-10-06T00:42:43Z"
lastmod: "2026-10-06T00:43:10Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:vm2_project:vm2:*:*:*:*:*:node.js:*:*
tags:
  - sandbox-escape
  - code-execution
  - javascript
  - rce
  - vulnerability
  - nodejs
vendors:
  - vm2
products:
  - vm2 (<= 3.11.7)
  - vm2 (<= 3.11.6)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This can, still, be used to escape the sandbox, one example (I'm sure there's other ways as well), is via console._stdout/console._stderr
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: By overwriting EventEmitter.prototype.emit with a function, and making process emit an event, we can execute code with this being process.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The sandboxed code uses the leaked proxy to reach the host process object and execute arbitrary commands via child_process.execSync.
    confidence_band: high
cves:
  - id: CVE-2026-92955
    cvss: 10
    epss: 0.00712
references:
  - https://github.com/advisories/GHSA-88hf-g992-jg85
  - https://github.com/patriksimek/vm2/security/advisories/GHSA-vwrp-x96c-mhwq
  - https://github.com/patriksimek/vm2/security/advisories/GHSA-v6mx-mf47-r5wg
  - https://github.com/patriksimek/vm2/security/advisories/GHSA-grj5-jjm8-h35p
  - https://github.com/patriksimek/vm2/security/advisories/GHSA-47x8-96vw-5wg6
  - https://github.com/advisories/GHSA-x965-fc75-jpqh
  - https://github.com/advisories/GHSA-j3hm-6rg5-mchv
action_plan:
  priority: immediate_escalation
  owners:
    - Application Security
    - Development Team
  immediate_actions:
    - action: Inventory all internal applications and services utilizing the vm2 package.
      owner: Development Team
      due: 24h
      evidence: CVE-2026-92955 affects all versions of vm2 <= 3.11.7.
  mitigation_plan:
    - priority: immediate
      action: Update vm2 to 3.11.8 or later
      owner: Application Security
      addresses: CVE-2026-92955
      evidence: The advisory states it was never patched in previous related reports.
updates:
  - at: "2026-10-06T00:43:01Z"
    level: L2
    summary: added coverage for vm2 (<= 3.11.7)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-x965-fc75-jpqh
  - at: "2026-10-06T00:43:10Z"
    level: L2
    summary: added coverage for vm2 (<= 3.11.6)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-j3hm-6rg5-mchv
---

The vm2 library, a popular JavaScript sandbox for executing untrusted code, contains a critical sandbox escape vulnerability tracked as CVE-2026-92955. The vulnerability affects all versions of the vm2 package up to and including 3.11.7. An attacker can exploit this flaw by leveraging the host's `__proto__` getter and setter to traverse the prototype chain of inherited console streams (specifically `console._stdout` and `console._stderr`). By accessing these objects, an attacker can modify `EventEmitter.prototype.emit`, allowing them to execute arbitrary code within the host process context. This method successfully bypasses Node.js security features such as `--disallow-code-generation-from-strings`, which typically prevents common sandbox breakout techniques. Successful exploitation results in full remote code execution on the host server.

## Attack Chain

1. An attacker identifies a target application utilizing the `vm2` NodeVM implementation with default `console: 'inherit'` settings.
2. The attacker injects malicious JavaScript code into the application which is subsequently processed by the vulnerable `NodeVM` instance.
3. The code utilizes `__lookupGetter__` to identify and access the host's `__proto__` getter for the `console._stderr` stream object.
4. By iterating through the prototype chain of the stream, the code climbs from the stream to the `EventEmitter` prototype.
5. The attacker overwrites the `EventEmitter.prototype.emit` method with a custom function.
6. The injected code forces the `process` object to emit an event (e.g., `exit` or `unhandledRejection`).
7. The modified `emit` method triggers, executing the attacker-supplied payload, such as invoking `child_process.execSync`.
8. Final objective achieved: Remote code execution on the host system.

## Impact

Successful exploitation of CVE-2026-92955 grants an attacker the ability to escape the isolated environment and execute arbitrary shell commands on the underlying host infrastructure. This presents a high risk for any service relying on vm2 for tenant or code isolation, potentially leading to total system compromise, data theft, and unauthorized persistence.

## Recommendation

1. Upgrade the vm2 package to a version that provides a patch for CVE-2026-92955, or replace the library if it is officially deprecated and unmaintained.
2. If an immediate upgrade is not possible, audit all applications using `NodeVM` to ensure they do not use `console: 'inherit'` or disable access to built-in modules where possible.
3. Restrict the usage of `vm2` to environments that do not require processing of untrusted input if the security architecture cannot guarantee isolation.
