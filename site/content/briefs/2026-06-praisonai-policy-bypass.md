---
title: PraisonAI Recipe Policy Bypass via YAML Workflow Approval
slug: 2026-06-praisonai-policy-bypass
description: A policy bypass vulnerability in PraisonAI (CVE-NONE) allows untrusted recipes to self-approve and execute default-denied critical shell tools, such as `execute_command`, by declaring them in `workflow.yaml` instead of `TEMPLATE.yaml requires.tools`, leading to arbitrary command execution with the privileges of the PraisonAI process.
date: "2026-06-18T15:01:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - application-vulnerability
  - policy-bypass
  - remote-code-execution
  - praisonai
  - python
vendors:
  - MervinPraison
products:
  - PraisonAI (>= 4.5.87, < 4.6.61)
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-7qw2-w5rc-37x2
rules:
  - title: Detect PraisonAI Spawning Suspicious Shell Process (Windows)
    description: Detects PraisonAI (Python interpreter) spawning common Windows shell processes, indicative of potential arbitrary command execution due to the policy bypass vulnerability. This rule focuses on the consequence of the PraisonAI policy bypass.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1059.001
      - T1059.003
      - T1218
    data_sources:
      - process_creation
      - windows
  - title: Detect PraisonAI Spawning Suspicious Shell Process (Linux)
    description: Detects Python interpreter running PraisonAI code spawning common Linux shell processes, indicative of potential arbitrary command execution due to the policy bypass vulnerability. This rule focuses on the consequence of the PraisonAI policy bypass.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1059.004
      - T1059.006
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical policy bypass vulnerability affects PraisonAI, a recipe execution platform, specifically versions `v4.5.87` through `v4.6.57`. The platform's security model intends to block "dangerous tools" (e.g., `execute_command`) unless an operator explicitly allows them via `allow_dangerous_tools=True`. However, an untrusted recipe can circumvent this control. By crafting a `workflow.yaml` that declares a default-denied tool within an agent's `tools` section and simultaneously using a top-level `approve:` directive, the recipe can effectively self-approve the dangerous tool. This bypasses the initial security policy that only checks `TEMPLATE.yaml requires.tools`, enabling the recipe to execute arbitrary commands without operator consent. The vulnerability affects both local CLI usage and HTTP recipe-runner deployments, with potentially higher severity if exposed to authenticated users.

## Attack Chain

1.  **Attacker crafts malicious PraisonAI recipe**: The attacker prepares a recipe consisting of a `workflow.yaml` that declares a default-denied critical tool (e.g., `execute_command`) under an agent's `tools` section and includes `approve: [execute_command]` at the top level, while ensuring the `TEMPLATE.yaml requires.tools` section does not list any dangerous tools.
2.  **Operator runs untrusted recipe**: An operator or user runs the attacker-controlled recipe through the PraisonAI local CLI or an exposed HTTP recipe runner, critically without specifying `allow_dangerous_tools=True`.
3.  **Initial policy check bypassed**: `PraisonAI`'s `_check_tool_policy()` function inspects only the `TEMPLATE.yaml requires.tools` list. Since the malicious `workflow.yaml` avoids listing dangerous tools there, the recipe passes this initial security gate.
4.  **`YAMLWorkflowParser` processes `workflow.yaml`**: During the `_execute_steps_workflow()` phase, `YAMLWorkflowParser` parses the `workflow.yaml`, resolving agent-level `tools:` declarations and extracting the top-level `approve:` directives.
5.  **Workflow self-approves dangerous tools**: The `Workflow.start()` method invokes `set_yaml_approved_tools()`, which registers the tools specified in the `approve:` directive (including the dangerous `execute_command`) within the application's approval context, effectively self-approving them.
6.  **Agent executes dangerous command**: When the PraisonAI agent within the workflow attempts to utilize the `execute_command` tool, it is treated as pre-approved due to the bypass, allowing the agent to proceed with its execution.
7.  **Arbitrary command execution**: The `execute_command` tool then executes arbitrary operating system commands specified by the attacker within the `workflow.yaml`, inheriting the privileges of the underlying PraisonAI process.
8.  **Impact**: This unapproved command execution can lead to remote code execution, data exfiltration, system compromise, or facilitate further lateral movement within the compromised environment.

## Impact

This policy bypass allows an untrusted recipe to execute arbitrary commands with the privileges of the PraisonAI process. If an operator runs such a recipe, or if a PraisonAI HTTP recipe runner is exposed to users who can choose recipe names or URIs, successful exploitation can lead to full system compromise. The exact trigger for command execution depends on the specific workflow and model/tool-call path, but the core policy boundary is breached before execution. This impacts both local CLI usage of PraisonAI and deployments utilizing the HTTP recipe runner, potentially escalating to an authenticated remote execution issue if the API is accessible.

## Recommendation

*   **Patch `PraisonAI`**: Upgrade `PraisonAI` to version `4.6.61` or later immediately to address the vulnerability described in the GHSA advisory.
*   **Monitor `process_creation` logs**: Deploy the Sigma rules provided in this brief to detect suspicious command execution originating from `PraisonAI` processes.
*   **Enable Sysmon logging**: Ensure Sysmon process creation and command line logging (Event ID 1) is enabled on all Windows systems running PraisonAI to facilitate detection of spawned shell processes.
