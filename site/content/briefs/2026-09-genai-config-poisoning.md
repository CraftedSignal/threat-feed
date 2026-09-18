---
title: GenAI Tool Configuration Poisoning via MCP Server Injection
slug: 2026-09-genai-config-poisoning
description: Adversaries are targeting configuration files of popular GenAI tools to inject malicious Model Context Protocol (MCP) servers, enabling persistence, arbitrary command execution, and data exfiltration.
date: "2026-09-18T19:10:08Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - persistence
  - genai-security
  - supply-chain
vendors:
  - Anthropic
  - Microsoft
  - Google
  - Ollama
  - Cursor
  - Codeium
products:
  - Cursor
  - Claude
  - GitHub Copilot
  - Ollama
  - Codex
  - Gemini
  - Grok
  - Windsurf
  - OpenClaw
  - Moltbot
affected_os:
  - Windows
  - macOS
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1556
    technique_name: Modify Authentication Process
    evidence: Adversaries may inject malicious MCP server configurations to hijack AI agents.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: Unauthorized MCP servers added to these configs execute arbitrary commands when the AI tool is next invoked.
    confidence_band: high
rules:
  - title: Detect Unusual Process Modifying GenAI Configuration File
    description: Detects unauthorized processes modifying GenAI tool configuration files to inject malicious MCP server configurations.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1556
      - T1574
    data_sources:
      - process_creation
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review GenAI configuration file integrity
      owner: SOC
      due: 48h
      evidence: Source documentation of MCP injection vectors
  hunt_leads:
    - lead: Search for unauthorized modifications to ~/.cursor and ~/.claude directories
      technique_id: T1556
      data_needed:
        - File integrity logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source highlights these as primary targets
  mitigation_plan:
    - priority: short_term
      action: Enforce strict write permissions on GenAI configuration directories
      owner: IT Operations
      addresses: Unauthorized file modification
      evidence: Configuration poisoning prevention
---

Adversaries are actively targeting configuration files associated with Generative AI (GenAI) development tools, including Cursor, Claude, GitHub Copilot, and Ollama. By modifying these configuration files to include malicious Model Context Protocol (MCP) servers, attackers can establish persistence, execute arbitrary commands on the host system, exfiltrate sensitive data, or establish command-and-control (C2) channels. 

The attack surface encompasses various methods: malware or malicious scripts performing direct filesystem modifications, supply chain compromises within developer dependencies, and prompt injection attacks that leverage an AI agent's inherent capabilities to modify its own configuration settings. Because MCP servers are designed to interface with the host environment, injecting unauthorized servers allows an attacker to inherit the permissions and context of the AI tool, effectively hijacking the agent's workflow. This threat is particularly critical for developers and automated CI/CD pipelines that rely on these tools for code generation and systems orchestration.

## Attack Chain

1. Attacker gains initial access to the target host through phishing, malware, or compromised dependencies.
2. Attacker performs local reconnaissance to locate GenAI configuration directories (e.g., ~/.cursor, ~/.claude, ~/.config/github-copilot).
3. Attacker executes a process to modify the targeted configuration file (e.g., mcp.json or settings.json) to register a malicious MCP server endpoint.
4. The malicious configuration is saved to the disk via standard filesystem modification events.
5. The GenAI tool is invoked by the user or an automated process.
6. The GenAI tool loads the malicious MCP server definition from the poisoned configuration file upon startup.
7. The malicious MCP server triggers the execution of arbitrary commands or scripts on the host.
8. Attacker achieves persistence or exfiltrates data through the established agent context.

## Impact

Successful exploitation results in arbitrary code execution on developer machines and build servers. This can lead to the compromise of source code repositories, credential theft (API keys, SSH tokens), and the introduction of supply chain backdoors into software projects. The scope of impact extends to any organization utilizing LLM-based development assistants that support the Model Context Protocol.

## Recommendation

Prioritize the monitoring of configuration file modifications for GenAI development tools to identify unauthorized changes. 
- Deploy the provided Sigma rule to monitor for unusual modifications to identified GenAI configuration paths.
- Audit existing MCP server configurations for unauthorized or unknown server URLs.
- Implement restrictive filesystem permissions on configuration directories for GenAI tools to prevent unauthorized write access by non-standard processes.
- Rotate API keys, credentials, and tokens associated with GenAI accounts if unauthorized configuration changes are detected.
