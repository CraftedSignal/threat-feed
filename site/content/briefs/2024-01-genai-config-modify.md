---
title: Unusual Modification of GenAI Tool Configuration File
slug: 2024-01-genai-config-modify
description: This rule detects unusual modifications to GenAI tool configuration files, potentially indicating an attacker injecting malicious MCP server configurations to hijack AI agents for persistence, command and control, or data exfiltration.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - genai
  - configuration-modification
  - defense-evasion
vendors:
  - Anthropic
  - Cursor
  - GitHub
  - Ollama
products:
  - Claude
  - Copilot
  - Cursor
  - Ollama
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1556
    technique_name: Modify Authentication Process
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1554
    technique_name: Compromise Host Software Binary
references:
  - https://modelcontextprotocol.io/
  - https://www.cybereason.com/blog/security-research/weaponized-ai-how-cybercriminals-exploit-mcp-for-account-takeover
  - https://glama.ai/blog/2025-11-11-the-lethal-trifecta-securing-model-context-protocol-against-data-flow-attacks
  - https://www.elastic.co/security-labs/elastic-advances-llm-security
rules:
  - title: Detect Unusual Process Modifying GenAI Configuration File - Generic
    description: Detects processes not normally associated with GenAI tools modifying their configuration files.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1556
    data_sources:
      - file_event
      - windows
  - title: Detect Suspicious Process Modifying GenAI Configuration File - Specific Paths
    description: Detects file modification events on specific GenAI configuration file paths.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1556
    data_sources:
      - file_event
      - windows
  - title: Detect process executable changing the config file
    description: Detects processes not normally associated with GenAI tools modifying their configuration files by inspecting the `process.executable` field.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1556
    data_sources:
      - file_event
      - windows
rules_count: 3
---

This detection identifies suspicious modifications to configuration files associated with Generative AI (GenAI) tools such as Cursor, Claude, Copilot, and Ollama. Attackers may attempt to inject malicious Model Context Protocol (MCP) server configurations into these files. This allows them to hijack AI agents for various malicious purposes, including persistence, establishing command and control (C2) channels, or exfiltrating sensitive data. The attack vectors can include direct modification via malware or compromised scripts, supply chain attacks through tainted dependencies, and prompt injection attacks where the GenAI tool is manipulated into altering its own settings. Successful modification allows unauthorized MCP servers to execute arbitrary commands upon subsequent invocations of the affected AI tool. The timeframe for detection looks back 9 months.

## Attack Chain

1.  **Initial Compromise:** An attacker gains initial access via malware, compromised scripts, or supply chain vulnerabilities targeting GenAI development environments.
2.  **Configuration Discovery:** The attacker identifies the location of GenAI tool configuration files, such as `.cursor/mcp.json`, `.claude/`, or `.config/github-copilot/`.
3.  **Malicious Modification:** The attacker modifies the configuration file, injecting a malicious MCP server URL or unauthorized plugin configurations. This could be achieved through direct file modification using scripting tools, or via prompt injection techniques.
4.  **Persistence via MCP:** The attacker leverages the injected malicious MCP server for persistence. The GenAI tool will load the attacker's server on next invocation.
5.  **Command and Control:** The injected MCP server establishes a command and control (C2) channel, allowing the attacker to remotely control the compromised AI agent.
6.  **Data Exfiltration or Code Execution:** Once the MCP server is running, the attacker executes arbitrary commands or exfiltrates sensitive data via the compromised AI agent. This data can include API keys, proprietary code, or customer data accessible by the GenAI tool.
7.  **Lateral Movement:** The attacker uses the compromised GenAI tool as a pivot point to move laterally within the network, accessing other sensitive systems or data.

## Impact

A successful attack can lead to the compromise of sensitive data handled by the GenAI tool, including API keys, source code, and user data. The attacker could also use the compromised AI agent for persistence, allowing them to maintain a foothold within the targeted environment. Successful exploitation could lead to significant data breaches, intellectual property theft, and reputational damage. The rule's description mentions the Cybereason blog on weaponized AI and MCPs, noting it being used for account takeover.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect unusual processes modifying GenAI configuration files based on the file paths specified in the `file.path` field of the rule.
*   Investigate any alerts generated by the Sigma rule by examining the modifying process's origin, parent process tree, and network connections.
*   Monitor file integrity using tools like Sysmon or auditd on the GenAI configuration file paths to detect unauthorized modifications.
*   Implement network-level blocking for any unauthorized MCP server URLs discovered in compromised configuration files.
*   Rotate any potentially exposed API keys or credentials that may have been compromised through the GenAI configuration files.
