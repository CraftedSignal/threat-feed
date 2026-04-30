---
title: GenAI Tool Access to Sensitive Files for Credential Harvesting and Persistence
slug: 2024-01-genai-sensitive-file-access
description: This brief outlines the threat of attackers leveraging GenAI tools to access sensitive files containing credentials, SSH keys, browser data, and shell configurations for credential access and persistence.
date: "2026-04-22T16:34:10Z"
type: advisory
types:
  - advisory
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

Attackers are increasingly exploiting GenAI tools to automate the discovery and exfiltration of sensitive information from compromised systems. This involves using GenAI agents to systematically scan file systems for credentials, API keys, tokens, and other secrets. Access to credential stores (.aws/credentials, .ssh/id_*) indicates credential harvesting, while modifications to shell configuration files (.bashrc, .zshrc) point to persistence attempts.  The observed activity leverages legitimate GenAI tool functionality, making it difficult to distinguish between benign use and malicious intent.  This technique has become more prevalent since late 2025, with attackers refining methods to instruct GenAI agents to specifically target and exfiltrate sensitive files. Defenders must monitor for unusual file access patterns by GenAI processes.

## Attack Chain

1.  Attacker gains initial access to a system via phishing or exploiting a software vulnerability.
2.  Attacker installs or deploys a GenAI tool (e.g., LM Studio, Claude, Copilot) on the compromised system.
3.  The attacker configures the GenAI tool to scan the file system for specific file names and patterns associated with sensitive data (credentials, keys, cookies).
4.  The GenAI tool accesses files such as `.aws/credentials`, `.ssh/id_rsa`, browser login databases (e.g., `Login Data`, `logins.json`, `Cookies`), and other credential stores.
5.  The GenAI tool may modify shell configuration files (`.bashrc`, `.zshrc`) to establish persistence.
6.  The GenAI tool stages the collected data for exfiltration.
7.  The attacker exfiltrates the harvested credentials and data to an external server.
8.  The attacker uses the stolen credentials to gain unauthorized access to other systems or cloud resources.

## Impact

Successful exploitation can lead to widespread credential compromise, allowing attackers to move laterally within a network, access sensitive data, and potentially disrupt critical business operations. A single compromised developer workstation could expose cloud infrastructure credentials, impacting hundreds of systems and services. The use of GenAI tools allows for rapid and automated credential harvesting, significantly increasing the scale and speed of potential breaches. Sectors at high risk include software development, cloud computing, and any organization that relies heavily on API keys and secrets for authentication.

## Recommendation

*   Deploy the Sigma rule `GenAI Process Accessing Sensitive Files` to your SIEM to detect GenAI tools accessing sensitive files. Tune for your environment to reduce false positives.
*   Monitor file access events, specifically looking for GenAI processes (ollama, lmstudio, claude) accessing files with names like `credentials`, `id_rsa`, `logins.json`, and `.bashrc`, as outlined in the Sigma rule.
*   Implement stricter access controls and monitoring for sensitive directories like `.aws`, `.ssh`, and browser profile directories.
*   Regularly audit and rotate credentials, API keys, and tokens, especially those stored in files.
*   Educate developers and users about the risks of using GenAI tools to handle sensitive data.
