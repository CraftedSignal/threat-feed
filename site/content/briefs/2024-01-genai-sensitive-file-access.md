---
title: GenAI Tool Access to Sensitive Files for Credential Harvesting and Persistence
slug: 2024-01-genai-sensitive-file-access
description: This brief outlines the threat of attackers leveraging GenAI tools to access sensitive files containing credentials, SSH keys, browser data, and shell configurations for credential access and persistence.
date: "2026-04-22T16:34:10Z"
severities:
  - high
tags:
  - credential-access
  - genai
  - file-access
  - persistence
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1037
    technique_name: Boot or Logon Initialization Scripts
references:
  - https://atlas.mitre.org/techniques/AML.T0085
  - https://atlas.mitre.org/techniques/AML.T0085.001
  - https://atlas.mitre.org/techniques/AML.T0055
  - https://glama.ai/blog/2025-11-11-the-lethal-trifecta-securing-model-context-protocol-against-data-flow-attacks
  - https://www.elastic.co/security-labs/elastic-advances-llm-security
  - https://specterops.io/blog/2025/11/21/an-evening-with-claude-code
rules:
  - title: GenAI Process Accessing Sensitive Files
    description: Detects when GenAI tools access sensitive files such as cloud credentials, SSH keys, browser password databases, or shell configurations.
    platform: sigma
    severity: high
    tactics:
      - collection
      - credential_access
      - persistence
    techniques:
      - T1005
      - T1037
      - T1552.001
    data_sources:
      - file_event
      - windows
  - title: GenAI Process Modifying Shell Configuration Files
    description: Detects when GenAI tools modify shell configuration files, potentially for persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1037.004
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Attackers are increasingly exploiting GenAI tools to automate the discovery and exfiltration of sensitive information from compromised systems. This involves using GenAI agents to systematically scan file systems for credentials, API keys, tokens, and other secrets. Access to credential stores (.aws/credentials, .ssh/id_*) indicates credential harvesting, while modifications to shell configuration files (.bashrc, .zshrc) point to persistence attempts.  The observed activity leverages legitimate…
