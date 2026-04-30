---
title: Budibase Command Injection Vulnerability in Bash Automation Step
slug: 2026-04-budibase-cmd-injection
description: A command injection vulnerability exists in Budibase's bash automation step due to insufficient sanitization, allowing attackers with automation modification access to inject arbitrary shell commands, leading to remote code execution.
date: "2026-04-04T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - command-injection
  - rce
  - budibase
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-gjw9-34gf-rp6m
rules:
  - title: Detect Suspicious Budibase Bash Automation Command Injection Attempts
    description: Detects attempts to exploit the command injection vulnerability in Budibase's bash automation step by identifying suspicious shell commands within automation workflow configurations.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Detect Potentially Malicious Commands Executed by Budibase
    description: Detects the execution of potentially malicious commands by the Budibase process, indicating a possible exploitation of the command injection vulnerability.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A command injection vulnerability has been identified in Budibase versions prior to 3.33.4, specifically within the bash automation step located in `packages/server/src/automations/steps/bash.ts`. This flaw allows an attacker with permissions to create or modify automation workflows to inject arbitrary shell commands. The vulnerability stems from the usage of `execSync` to execute user-supplied commands without adequate sanitization or validation. Input is processed through `processStringSync`, enabling template interpolation that can be exploited for command injection. Successful exploitation could lead to remote code execution, complete system compromise, data exfiltration, and lateral movement within the affected infrastructure. Defenders should prioritize patching or implementing mitigations to prevent exploitation.

## Attack Chain

1. An attacker gains access to the Budibase platform with the ability to create or modify automation workflows.
2. The attacker crafts a malicious payload containing shell commands embedded within template syntax (e.g., `$(rm -rf /)`, `; malicious-command`, `| malicious-command`).
3. The attacker injects the malicious payload into the `inputs.code` field of a bash automation step.
4. The `processStringSync` function processes the user-supplied input, interpolating the template syntax and generating a command string.
5. The `execSync` function executes the crafted command string without proper sanitization.
6. The injected shell commands execute on the server with the privileges of the Budibase application.
7. The attacker achieves remote code execution, potentially gaining control of the server.
8. The attacker can then perform actions such as data exfiltration, lateral movement, or system compromise.

## Impact

Successful exploitation of this vulnerability can lead to severe consequences, including remote code execution (RCE) on the Budibase server. This could result in complete system compromise, allowing attackers to steal sensitive data, modify system configurations, or use the compromised system as a pivot point for further attacks within the network. While the exact number of affected organizations is unknown, any Budibase instance running a version prior to 3.33.4 is potentially vulnerable.

## Recommendation

- Immediately disable the bash automation step in production environments to prevent further exploitation.
- Upgrade Budibase to version 3.33.4 or later, where this vulnerability is addressed.
- Implement the command sanitization and validation techniques outlined in the provided example fix.
- If upgrading is not immediately feasible, implement a whitelist of allowed commands to restrict the functionality of the bash automation step.
- Enable and review Budibase application logs for any unusual or suspicious command execution patterns (reference: Overview section).
