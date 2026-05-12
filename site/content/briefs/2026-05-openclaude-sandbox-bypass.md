---
title: OpenClaude Sandbox Bypass via Model-Controlled `dangerouslyDisableSandbox` Input
slug: 2026-05-openclaude-sandbox-bypass
description: 'A sandbox bypass vulnerability exists due to the `dangerouslyDisableSandbox` parameter being exposed as part of the BashTool input schema, allowing an untrusted LLM to bypass the sandbox for any command and achieve host-level code execution due to the default `allowUnsandboxedCommands: true` setting.'
date: "2026-05-12T16:18:29Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sandbox-bypass
  - llm
  - code-execution
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-m77w-p5jj-xmhg
rules:
  - title: Detect OpenClaude Sandbox Bypass Attempt
    description: Detects attempts to bypass the OpenClaude sandbox by setting 'dangerouslyDisableSandbox' to true in the tool_use input.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect OpenClaude Sandbox Bypass - Suspicious Network Connection
    description: 'Detects a suspicious network connection initiated by a process where the command line contains ''dangerouslyDisableSandbox'': true.'
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
  - title: Detect OpenClaude Sandbox Bypass - File Exfiltration Attempt
    description: 'Detects a file exfiltration attempt by a process where the command line contains ''dangerouslyDisableSandbox'': true, indicating a bypassed sandbox environment.'
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

A critical vulnerability exists in OpenClaude due to the exposure of the `dangerouslyDisableSandbox` parameter within the BashTool input schema. This flaw allows an untrusted Large Language Model (LLM), which is assumed to be susceptible to prompt injection, to disable the sandbox by setting `dangerouslyDisableSandbox` to `true` in a `tool_use` response. Coupled with the default setting of `allowUnsandboxedCommands: true`, this bypass grants the LLM the ability to execute arbitrary commands on the host system, leading to complete host-level code execution. This vulnerability highlights a critical security flaw in the project's design, where a model-controlled input directly influences a security-sensitive boundary. The vulnerability is confirmed in the `security-tests/integration/scenario-sandbox-bypass.sh` and `security-tests/unit/test-sandbox-bypass.ts` tests.

## Attack Chain

1. The attacker injects a malicious prompt into the OpenClaude LLM.
2. The injected prompt instructs the LLM to generate a `tool_use` block.
3. The `tool_use` block specifies the "Bash" tool with a command to execute.
4. The `tool_use` block includes the `"dangerouslyDisableSandbox": true` parameter.
5. The `shouldUseSandbox()` function evaluates `input.dangerouslyDisableSandbox` and `areUnsandboxedCommandsAllowed()`, both returning true.
6. The `shouldUseSandbox()` function returns `false`, bypassing the sandbox.
7. The specified command executes on the host system without sandbox confinement, allowing arbitrary code execution.
8. The attacker achieves the objective, such as exfiltrating sensitive data or gaining persistent access to the system.

## Impact

Successful exploitation of this vulnerability allows an attacker to achieve arbitrary code execution on the host system running OpenClaude. This can lead to the complete compromise of the system, including the exfiltration of sensitive data, installation of malware, and persistent access. The default configuration of `allowUnsandboxedCommands: true` makes systems vulnerable out-of-the-box. While specific victim counts are unknown, the impact is critical due to the potential for widespread compromise.

## Recommendation

*   Set `allowUnsandboxedCommands` to `false` in the OpenClaude configuration to mitigate the vulnerability as shown in the unit test `security-tests/unit/test-sandbox-bypass.ts`.
*   Deploy the Sigma rule "Detect OpenClaude Sandbox Bypass Attempt" to identify potential exploitation attempts.
*   Audit all existing integrations of OpenClaude to ensure that prompts are properly sanitized to prevent prompt injection attacks, which can trigger the vulnerability described in this brief.
*   Review and update the `shouldUseSandbox()` function to ensure that critical security decisions are not controlled by untrusted inputs from the LLM, as described in `src/tools/BashTool/shouldUseSandbox.ts`.
