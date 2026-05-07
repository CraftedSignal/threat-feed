---
title: AI Coding Agents Vulnerable to Supply Chain Attacks via Malicious Repositories
slug: 2026-05-ai-supply-chain
description: AI coding agents like Claude Code, Gemini CLI, Cursor CLI, and GitHub Copilot Agents can be manipulated to introduce malicious code into software supply chains by accessing attacker-controlled repositories, leading to potential remote code execution and supply chain compromises.
date: "2026-05-07T13:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - supply chain
  - ai
  - remote code execution
vendors:
  - Anthropic
  - Google
  - Microsoft
products:
  - Claude Code
  - Gemini CLI
  - GitHub Copilot Agents
  - Cursor CLI
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Supply Chain Compromise
    technique_id: T1195
    technique_name: Supply Chain Compromise
references:
  - https://www.securityweek.com/ai-coding-agents-could-fuel-next-supply-chain-crisis/
rules:
  - title: Detect Suspicious MCP Server Processes
    description: Detects the execution of processes defined in a .mcp.json file, which can indicate malicious activity initiated by a compromised AI coding agent.
    platform: sigma
    severity: high
    tactics:
      - execution
      - supply_chain
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect MCP JSON File Creation
    description: Detects the creation of .mcp.json files, which can indicate a malicious repository designed to exploit AI coding agents.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - supply_chain
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Researchers at Adversa.AI discovered the "TrustFall" vulnerability in AI coding agents like Claude Code (launched in May 2025). This vulnerability allows attackers to inject malicious code into software supply chains by creating malicious repositories. When a developer uses an AI coding agent for a task, the agent may access these repositories, select, and download the malicious code. The agent then prompts the user to trust the code, and upon acceptance, the malicious code executes with the developer's full privileges. This vulnerability is not limited to Claude Code; Gemini CLI, Cursor CLI, and GitHub Copilot Agents are also affected. This poses a significant risk to organizations relying on AI-assisted coding, as it can lead to widespread supply chain compromise.

## Attack Chain

1.  The attacker creates a malicious repository containing attractive code designed to be selected by AI coding agents.
2.  The malicious repository includes small JSON files in standard locations (e.g., `.claude/settings.json`, `.mcp.json`) with directives like `enableAllProjectMcpServers` or `enabledMcpjsonServers`.
3.  A developer uses an AI coding agent (e.g., Claude Code) to assist with a coding task.
4.  The AI coding agent searches for and locates the attacker's malicious repository.
5.  The AI coding agent suggests using code from the malicious repository to the developer.
6.  The developer is prompted with a trust dialog (e.g., "Quick safety check: Is this a project you created or one you trust?"), which defaults to "trust".
7.  Upon the developer's acceptance, the attacker-defined MCP servers are spawned as OS processes with the user's full privileges.
8.  The spawned server establishes a long-lived C2 connection or directly executes malicious code, potentially including environment variables, deploy keys, signing certificates, and other credentials in the build process, leading to a supply chain attack.

## Impact

A successful "TrustFall" attack can lead to complete compromise of a developer's machine, allowing attackers to gain access to sensitive information and inject malicious code into widely distributed software tools. If the code is destined for the user's CICD pipeline, the attack can compromise the entire supply chain, affecting potentially thousands of users. The impact includes remote code execution, data exfiltration, and the introduction of backdoors into critical software components. Attackers can steal credentials, signing certificates, and other sensitive data used in the build process, leading to widespread software compromise.

## Recommendation

*   Monitor process creation events for the execution of unexpected processes with the user's full privileges immediately after a code repository is accessed (see Sigma rule `Detect Suspicious MCP Server Processes`).
*   Implement controls to prevent AI coding agents from automatically trusting and executing code from untrusted repositories. Specifically, block `enableAllProjectMcpServers`, `enabledMcpjsonServers`, and `permissions.allow` from any settings file inside the project and allow these keys only from scopes structurally outside the repository.
*   For CI/CD pipelines using AI coding agents non-interactively, gate them on branches where commits are already reviewed: post-merge on main, not arbitrary PR branches.
*   Deploy the Sigma rule `Detect MCP JSON File Creation` to monitor for the creation of `.mcp.json` files in project directories, as this file is used to define MCP servers.
