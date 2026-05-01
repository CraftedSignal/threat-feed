---
title: GenAI Tools Accessing Sensitive Files for Credential Access and Persistence
slug: 2024-12-15-genai-sensitive-file-access
description: This threat brief details the detection of GenAI tools accessing sensitive files containing credentials, SSH keys, browser data, and shell configurations, indicating potential credential harvesting and persistence attempts by attackers leveraging GenAI agents.
date: "2026-05-01T22:46:51Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - genai
  - credential-access
  - persistence
  - collection
vendors:
  - Elastic
products:
  - Elastic Endpoint Security
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
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/credential_access_genai_process_sensitive_file_access.toml
rules:
  - title: GenAI Process Accessing Sensitive Files
    description: Detects GenAI tools accessing sensitive files such as cloud credentials, SSH keys, browser password databases, or shell configurations.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - persistence
    techniques:
      - T1037.004
      - T1552.001
    data_sources:
      - file_event
      - windows
  - title: GenAI Process Modifying Shell Configuration Files
    description: Detects GenAI tools writing to shell configuration files, which can indicate persistence attempts.
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

Attackers are increasingly leveraging GenAI agents to automate the discovery and exfiltration of sensitive information, including credentials, API keys, and tokens stored within files on compromised systems. The observed activity involves GenAI tools accessing critical files such as cloud credentials, SSH keys, browser password databases, and shell configuration files. Successful exploitation allows attackers to harvest credentials, gain unauthorized access to systems, and establish persistence mechanisms for continued access. The GenAI tools mentioned include ollama, textgen, lmstudio, claude, cursor, copilot, codex, jan, gpt4all, gemini-cli, genaiscript, grok, qwen, koboldcpp, llama-server, windsurf, zed, opencode, and goose. This activity highlights the emerging threat landscape of AI-assisted attacks and the need for robust detection and mitigation strategies.

## Attack Chain

1.  Initial compromise of a system through an unrelated vulnerability or social engineering.
2.  Installation or execution of a GenAI tool (e.g., ollama, lmstudio) on the compromised system.
3.  The GenAI tool is configured or instructed to scan the file system for sensitive files.
4.  The GenAI tool accesses files containing credentials, such as `.aws/credentials`, browser password databases (`Login Data`, `key3.db`), or SSH keys (`.ssh/id_*`).
5.  The GenAI tool exfiltrates the harvested credentials and API keys to a remote server controlled by the attacker.
6.  The attacker uses the stolen credentials to gain unauthorized access to cloud resources, internal systems, or other sensitive accounts.
7.  The GenAI tool attempts to modify shell configuration files (e.g., `.bashrc`, `.zshrc`) to establish persistence.
8.  Upon system restart or user login, the modified shell configuration executes malicious commands, granting the attacker persistent access.

## Impact

Successful exploitation of this threat can lead to significant data breaches, unauthorized access to critical systems, and persistent compromise of affected environments. Attackers can leverage stolen credentials to escalate privileges, move laterally within the network, and exfiltrate sensitive data. The number of victims and sectors targeted are currently unknown, but the potential impact is widespread given the increasing adoption of GenAI tools in various industries. Credential theft leads to financial loss, intellectual property theft, and reputational damage.

## Recommendation

*   Deploy the Sigma rule "GenAI Process Accessing Sensitive Files" to your SIEM to detect GenAI tools accessing sensitive files on endpoints.
*   Enable file access monitoring on systems where GenAI tools are used to capture access events for analysis.
*   Review and restrict the use of GenAI tools within the environment, especially concerning access to sensitive file paths.
*   Monitor for modifications to shell configuration files (e.g., `.bashrc`, `.zshrc`, `.profile`) as an indicator of persistence attempts.
*   Implement regular credential rotation policies to minimize the impact of stolen credentials.
