---
title: Claude Code OAuth Token Theft via MCP Hijacking
slug: 2026-05-claude-oauth-hijack
description: Attackers can silently redirect Claude Code MCP traffic to intercept OAuth tokens, enabling persistent access to connected SaaS platforms by modifying the ~/.claude.json file in a man-in-the-middle attack.
date: "2026-05-07T14:33:06Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - oauth
  - man-in-the-middle
  - credential access
vendors:
  - Anthropic
products:
  - Claude Code
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://www.securityweek.com/claude-code-oauth-tokens-can-be-stolen-through-stealthy-mcp-hijacking/
rules:
  - title: Detect Claude Code Configuration File Modification
    description: Detects modification of the ~/.claude.json file, which can indicate malicious attempts to redirect MCP traffic.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - persistence
    techniques:
      - T1550.001
    data_sources:
      - file_event
      - linux
  - title: Detect Suspicious NPM Package Installation with Lifecycle Hooks
    description: Detects the installation of NPM packages that register lifecycle hooks, potentially used to modify Claude Code settings.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1608
    data_sources:
      - process_creation
      - linux
  - title: Detect Outbound Connections from Claude Code to Unusual Ports
    description: Detects unusual outbound network connections from Claude Code processes, potentially indicating MCP traffic redirection.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 3
---

Mitiga researchers identified a vulnerability in Claude Code, an agentic system used by developers, that allows for the silent redirection of MCP (Management Control Plane) traffic. By exploiting this flaw, attackers can intercept OAuth tokens, effectively gaining a master key to all tools connected to the Claude Code MCP. The attack involves a man-in-the-middle technique where traffic is redirected through attacker-controlled infrastructure. This gives the attacker access to sensitive tokens stored in plain text within the ~/.claude.json configuration file. The vulnerability was reported to Anthropic on April 10, 2026, but was deemed 'out of scope' by the vendor.

## Attack Chain

1.  The attacker gains initial access to a machine with Claude Code configured and dynamic authorization MCP servers.
2.  The attacker installs a tailored npm package containing malicious code.
3.  The malicious npm registers a lifecycle hook that runs as part of the installation process.
4.  The post-installation hook locates common clone locations and populates the paths with a pre-configured trust dialog set to 'true', preventing future prompts.
5.  The hook opens the ~/.claude.json file and modifies the 'mcpServers' entry to include the attacker's proxy address.
6.  Claude Code connects to the attacker's proxy when initiating or refreshing the MCP session, routing the OAuth token through the attacker's infrastructure.
7.  The attacker intercepts the OAuth token, which is transmitted in plain text.
8.  The attacker uses the stolen OAuth token to access connected SaaS platforms with the same permissions as the user, bypassing MFA.

## Impact

A successful attack allows adversaries to steal OAuth tokens from Claude Code, granting them a "golden key" to access any tool connected to the MCP. The attacker achieves durable redirection of SaaS credentials into attacker-controlled infrastructure, invisible to the user and indistinguishable from legitimate traffic. This allows the attacker to bypass MFA and gain unauthorized access to sensitive data within connected SaaS applications.

## Recommendation

*   Monitor Claude Code configuration files, specifically the `~/.claude.json` file, for unauthorized modifications using file integrity monitoring rules.
*   Implement a Sigma rule to detect the execution of suspicious npm packages installing lifecycle hooks that modify MCP server URLs in the configuration file.
*   Monitor network connections originating from Claude Code processes for connections to unusual or external proxy addresses via a network connection monitoring rule.
