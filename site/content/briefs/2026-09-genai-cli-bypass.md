---
title: Unsafe Permission Bypass in GenAI CLI Agents
slug: 2026-09-genai-cli-bypass
description: The misuse of permission-bypass or auto-approval flags in GenAI CLI agents disables critical human-in-the-loop guardrails, creating significant risks for prompt injection and unauthorized autonomous system modification on developer workstations.
date: "2026-09-18T19:09:57Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Anthropic
  - OpenAI
  - Google
  - Microsoft
products:
  - Claude Code
  - Codex CLI
  - Gemini CLI
  - GitHub Copilot CLI
  - OpenCode
affected_os:
  - Linux
  - macOS
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: These modes are intended for isolated sandboxes but are frequently misused on internet-connected developer workstations, allowing prompt injection, compromised dependencies, or malicious skills to execute commands, modify files, or reach sensitive paths without confirmation.
    confidence_band: high
rules:
  - title: Detect GenAI CLI Started with Unsafe Permission Bypass Flags
    description: Detects the execution of various GenAI CLI agents using flags that disable human-in-the-loop permission prompts, such as --yolo or --dangerously-skip-permissions.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the GenAI CLI bypass detection rule.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific command line arguments associated with dangerous bypass modes.
  mitigation_plan:
    - priority: medium_term
      action: Enforce security policies disabling permission bypass flags for GenAI agents.
      owner: IT Operations
      addresses: Unauthorized AI Usage
      evidence: Source documentation identifies usage of these flags as a primary security risk.
---

GenAI coding agents are designed to assist developers by performing tasks such as file editing, command execution, and code generation. These tools incorporate security guardrails, typically requiring human approval before executing sensitive operations. However, various CLI tools support administrative or sandbox-intended flags that bypass these confirmation prompts, enabling autonomous operation. 

Defenders have observed these flags - such as `--yolo`, `--dangerously-skip-permissions`, or `--full-auto` - being misused on internet-connected developer workstations. This configuration eliminates human oversight, allowing compromised dependencies, malicious project configurations, or external prompt injection attacks to execute arbitrary shell commands, modify local files, and access sensitive environment credentials without user interaction. This behavior materially increases the blast radius for development environments, as the agent functions with the full privileges of the host user account.

## Impact

Successful exploitation of this configuration allows attackers to pivot from an initial prompt injection or dependency compromise into full code execution on the developer's workstation. This results in the potential exfiltration of source code, cloud credentials, and local environment variables, potentially leading to downstream supply chain attacks if the developer has access to production CI/CD pipelines.

## Recommendation

Detection engineering teams should focus on identifying the execution of GenAI agent binaries with permissive command-line arguments. 

* Deploy the provided Sigma rules to identify and alert on GenAI agents started with bypass flags in non-sandbox environments.
* Audit and restrict the usage of GenAI agent permission-bypass flags via organization-wide security policies.
* Audit active GenAI configurations, including MCP server settings and skill definitions, for unauthorized modifications.
* Ensure developers follow a "plan-only" or "default" permission mode for all interactive work on networked endpoints.
