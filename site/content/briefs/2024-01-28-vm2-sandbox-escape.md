---
title: vm2 NodeVM Nesting Bypass Allows Arbitrary Command Execution
slug: 2024-01-28-vm2-sandbox-escape
description: A vulnerability in vm2's NodeVM, when nesting is enabled, allows sandbox code to bypass require restrictions, enabling arbitrary OS command execution on the host.
date: "2024-01-28T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sandbox-escape
  - vm2
  - code-execution
products:
  - vm2 (<= 3.11.0)
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
  - https://github.com/advisories/GHSA-8hg8-63c5-gwmx
rules:
  - title: Detect vm2 Nesting Sandbox Escape via Child Process
    description: Detects the use of child_process within a vm2 sandbox with nesting enabled, indicating a potential sandbox escape attempt.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
  - title: Detect vm2 Nesting Sandbox Escape via Require vm2
    description: Detects the use of require('vm2') within a vm2 sandbox with nesting enabled, indicating a potential sandbox escape attempt.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A critical vulnerability exists in vm2 versions 3.11.0 and below, specifically impacting the `NodeVM` when the `nesting: true` option is enabled. This flaw allows untrusted code running within the sandbox to bypass the intended `require` restrictions, even when `require: false` is explicitly set. By exploiting this bypass, malicious code can gain access to the `vm2` module itself, create a new inner `NodeVM` with unrestricted permissions, and ultimately execute arbitrary OS commands on the host system. This can lead to complete compromise of applications relying on vm2 for secure code execution, affecting multi-tenant platforms, REPL services, and CI sandboxing environments. The vulnerability stems from how `nesting: true` overrides the `require` settings during module resolution, silently allowing access to `vm2` even when it should be blocked.

## Attack Chain

1.  The host application creates a `NodeVM` instance with `nesting: true` and `require: false` (or a restrictive require list) to sandbox untrusted code.
2.  The untrusted code within the sandbox calls `require('vm2')`. Due to the vulnerability, this succeeds despite the outer VM's require restrictions.
3.  The sandbox code obtains the `NodeVM` constructor from the required `vm2` module.
4.  The sandbox creates a new, inner `NodeVM` instance, specifying its own `require` configuration to include `child_process`.
5.  The inner `NodeVM` uses `child_process.execSync()` to execute an arbitrary OS command (e.g., `id`, `whoami`).
6.  The output of the executed command is converted to a string.
7.  The inner VM returns the command output to the outer VM.
8.  The outer VM returns the command output to the host application, effectively escaping the sandbox.

## Impact

Successful exploitation allows attackers to execute arbitrary OS commands as the user running the host Node.js process. This gives the attacker the ability to read and write files, potentially exfiltrate sensitive information (secrets, API keys, etc.), move laterally within the network the host resides on, and establish persistent access to the compromised system. Any application employing `vm2` with `nesting: true` to isolate untrusted code is vulnerable. This includes multi-tenant systems and CI/CD environments, posing a severe risk to infrastructure security. The vulnerability exists because developers expect `require: false` to provide a solid sandbox restriction, but enabling `nesting: true` silently overrides this expectation.

## Recommendation

*   Immediately upgrade to a patched version of `vm2` that addresses this vulnerability.
*   If upgrading is not immediately feasible, avoid using `nesting: true` in `NodeVM` configurations where untrusted code execution is involved.
*   Deploy the Sigma rule `Detect vm2 Nesting Sandbox Escape via Child Process` to identify potential exploitation attempts.
*   Enable process creation logging to support the detection rules.
*   Audit existing `NodeVM` configurations within your applications to identify instances where `nesting: true` is used in conjunction with restricted `require` settings.
*   Consider alternative sandboxing solutions that offer more robust module isolation if `vm2` cannot be adequately secured.
