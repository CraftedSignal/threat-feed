---
title: VM2 Sandbox Escape via Promise Species Manipulation
slug: 2026-05-vm2-sandbox-escape
description: A vulnerability in vm2 versions 3.10.3 and earlier allows attackers to bypass a previous sandbox escape fix by manipulating Promise species, leading to arbitrary code execution on the host system.
date: "2026-05-06T12:00:00Z"
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
  - npm
products:
  - vm2 (<= 3.10.3)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-24120
    cvss: 9.8
references:
  - https://github.com/advisories/GHSA-qvjj-29qf-hp7p
rules:
  - title: Detect Object.defineProperty Redefinition in VM2
    description: Detects attempts to redefine the Object.defineProperty function, potentially indicating a sandbox escape attempt in VM2.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1070
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Process Creation from Node.js with vm2
    description: Detects suspicious process creation events originating from Node.js processes potentially running vm2, indicating a possible sandbox escape.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A critical vulnerability exists within the vm2 npm package, specifically in versions 3.10.3 and earlier. This vulnerability stems from an insufficient fix for a prior sandbox escape issue (GHSA-cchq-frgv-rjh5). Attackers can bypass the intended security measures by manipulating the `species` property of Promise objects. The flaw lies in the ability to overwrite native JavaScript functions like `[].includes` and `Object.defineProperty`, which are used in the `resetPromiseSpecies` function. By preventing the proper resetting of the Promise species, attackers can achieve arbitrary code execution on the host system, effectively breaking out of the vm2 sandbox. This vulnerability was reported in GHSA-qvjj-29qf-hp7p, published May 5, 2026.

## Attack Chain

1. The attacker provides JavaScript code to be executed within the vm2 sandbox.
2. The code redefines `Object.defineProperty` to prevent modification of the `species` property.
3. The code defines an asynchronous function that returns an Error object with a Symbol as its name.
4. The `constructor` of the Promise is overwritten with a custom class that defines a specific `Symbol.species`.
5. The custom `Symbol.species` utilizes an executor that calls the reject function.
6. The reject function executes arbitrary code on the host system via `child_process.execSync`.
7. The attacker triggers the Promise's `then()` method.
8. The host system executes arbitrary commands, such as creating a file named "pwned".

## Impact

Successful exploitation of this vulnerability allows attackers to perform Remote Code Execution (RCE) on the host system. Given the nature of vm2 as a sandbox environment for running untrusted code, this vulnerability represents a significant security risk. If an attacker can run arbitrary code inside the context of a vm2 sandbox, they can leverage this vulnerability to compromise the underlying host system, potentially leading to data theft, system takeover, or other malicious activities.

## Recommendation

*   Upgrade to a patched version of the `vm2` package that addresses CVE-2026-24120.
*   Deploy the provided Sigma rule detecting attempts to redefine `Object.defineProperty` within the vm2 environment to your SIEM.
*   Monitor for unexpected process creation events originating from the vm2 process using the provided Sigma rule.
