---
title: vm2 NodeVM Sandbox Escape via node:test Builtin
slug: 2026-10-vm2-node-test-bypass
description: The vm2 sandboxing library fails to properly secure the 'node:test' builtin module in Node.js 24+, allowing an attacker to escape the sandbox via a double-prefix require and execute arbitrary host code.
date: "2026-10-01T20:20:11Z"
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
products:
  - vm2 (>= 3.9.6, <= 3.11.5)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Supplying --eval=<JavaScript> therefore executes arbitrary JavaScript in an unrestricted host Node process, outside the NodeVM sandbox.
    confidence_band: high
cves:
  - id: CVE-2026-92948
    cvss: 9.9
    epss: 0.00654
references:
  - https://github.com/advisories/GHSA-qhwx-74w5-xhxq
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92948
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Identify and audit all applications using vm2 in the environment to check for 'node:test' in builtin configurations.
      owner: SOC
      due: 24h
      evidence: Configuration prerequisite section of the brief.
  mitigation_plan:
    - priority: immediate
      action: Remove 'node:test' from all vm2 allowlists or move to an alternative sandboxing solution immediately.
      owner: IT Operations
      addresses: CVE-2026-92948
      evidence: Suggested remediation section of the brief.
---

The vm2 library (versions 3.9.6 through 3.11.5) contains a critical sandbox escape vulnerability (CVE-2026-92948) when running on Node.js 24 or newer. The issue arises from a failure to correctly restrict the `node:test` builtin module. When an embedder explicitly allows `node:test` within a `NodeVM` configuration, sandboxed code can bypass the intended restrictions by requesting the module using a double prefix, `require('node:node:test')`.

Normalization logic within `vm2` resolves this to the `node:test` module, providing the sandbox with a readonly proxy to the host's test-runner. Because this proxy forwards calls to the host implementation without sufficient API validation, an attacker can invoke `node:test.run()` and supply arbitrary `execArgv` flags. By passing flags such as `--eval`, the attacker can spawn a child process that executes arbitrary JavaScript in an unrestricted host Node.js environment, effectively escaping the vm2 sandbox boundary.

## Attack Chain

1. Attacker identifies a target application utilizing `vm2` with `node:test` explicitly enabled in the `require.builtin` configuration.
2. Attacker injects malicious JavaScript into the `NodeVM` sandbox environment.
3. Attacker invokes `require('node:node:test')` within the sandbox to bypass existing builtin restriction filters.
4. The `vm2` sandbox normalizes the path to `node:test` and grants access to the host's test-runner module.
5. Attacker executes `node:test.run()` within the sandbox, supplying a crafted object containing malicious `execArgv` parameters.
6. The `node:test` runner spawns a new Node.js child process using the attacker-supplied `execArgv` arguments.
7. The child process executes the attacker's payload (e.g., `--eval='require("fs").writeFileSync(...)'`) outside the sandbox, granting full access to the host system.

## Impact

Successful exploitation allows an attacker to break out of the vm2 sandbox and execute code with the privileges of the host Node.js process. This leads to full system compromise, including unauthorized access to the host filesystem, environment variables, network resources, and other sensitive host-side data. The impact is critical as it invalidates the security boundary provided by the vm2 library.

## Recommendation

1. Upgrade to a patched version of `vm2` if available or transition to more secure sandboxing solutions, as the `vm2` project has reached end-of-life.
2. Update the `DANGEROUS_BUILTINS` configuration in the `vm2` library to include `test` to block access to the `node:test` module at the source.
3. Audit existing configurations to identify and remove `node:test` from any `require.builtin` allowlists.
4. If test capabilities are required, implement a sandbox-local wrapper that does not expose the `run()` method, `execArgv`, or any other host-process control parameters.
