---
title: GenAI Process Performing Encoding/Chunking Prior to Network Activity
slug: 2024-01-genai-encoding-exfiltration
description: This rule detects GenAI processes performing encoding or chunking (base64, gzip, tar, zip) followed by outbound network activity, indicating data preparation for exfiltration.
date: "2024-01-03T18:22:38Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - genai
  - exfiltration
  - defense-evasion
vendors:
  - Ollama
  - LM Studio
products:
  - Ollama
  - LM Studio
  - Textgen
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1560
    technique_name: Archive Collected Data
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1560
    technique_name: Archive Collected Data
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1030
    technique_name: Data Transfer Size Limits
references:
  - https://atlas.mitre.org/techniques/AML.T0086
  - https://glama.ai/blog/2025-11-11-the-lethal-trifecta-securing-model-context-protocol-against-data-flow-attacks
  - https://www.elastic.co/security-labs/elastic-advances-llm-security
rules:
  - title: GenAI Process Encoding Before Outbound Network Connection
    description: Detects GenAI processes performing encoding or chunking (base64, gzip, tar, zip) followed by outbound network activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - exfiltration
    techniques:
      - T1027
      - T1030
    data_sources:
      - process_creation
      - windows
  - title: GenAI Python Encoding
    description: Detects python encoding activity after a GenAI process
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - exfiltration
    techniques:
      - T1027
      - T1030
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies a suspicious sequence of actions involving GenAI processes. Specifically, it flags instances where a GenAI process (or a child process) performs encoding or chunking operations (such as base64 encoding, gzip compression, or archiving with tar/zip) and is immediately followed by outbound network connections. This behavior suggests that an attacker is preparing data for exfiltration, potentially through manipulated GenAI prompts or agents. The attacker encodes or compresses data to obfuscate its contents and evade traditional detection mechanisms. While legitimate GenAI workflows rarely involve encoding data prior to network communication, attackers may leverage this technique to exfiltrate sensitive information from compromised environments. The rule specifically looks for processes like `ollama.exe`, `textgen.exe`, `lmstudio.exe`, and others, as well as common encoding utilities like `base64`, `gzip`, and `zip`. The detection logic incorporates command-line analysis to identify encoding activities within PowerShell, Python, and Node.js environments. This activity started being tracked in late 2025 and is relevant for defenders because it shows a specific technique to exfiltrate data.

## Attack Chain

1.  The attacker compromises a system with a GenAI application installed (e.g., LM Studio, Ollama).
2.  The attacker uses or manipulates the GenAI application to access sensitive data. This could involve using custom prompts or agents to extract data from local files or databases.
3.  The attacker initiates an encoding process using native tools like `base64`, `gzip`, `tar`, or `zip`, or scripting languages like PowerShell, Python, or Node.js. This step is intended to obfuscate the data. The command line will contain flags specific to encoding or compression.
4.  The encoding process creates a new file or data stream containing the encoded data.
5.  A network connection is established from the system to an external IP address, bypassing local or loopback addresses.
6.  The encoded data is transmitted over the network connection. This could be done via HTTP, FTP, or other protocols.
7.  The attacker receives the exfiltrated data on their remote server.
8.  The attacker may then delete the encoded file from the compromised system to further evade detection.

## Impact

Successful execution of this attack chain can lead to the exfiltration of sensitive data, including intellectual property, customer data, credentials, or other confidential information. This data breach can result in significant financial losses, reputational damage, legal liabilities, and regulatory penalties. The rule targets GenAI applications, which are becoming increasingly prevalent in various sectors.

## Recommendation

*   Deploy the following Sigma rule to detect GenAI processes performing encoding/chunking prior to network activity, and tune it for your specific GenAI environment.
*   Inspect process command-line arguments for unexpected use of encoding/chunking utilities (e.g., `base64`, `gzip`, `tar`, `zip`) launched from GenAI applications.
*   Monitor outbound network connections from systems running GenAI applications, filtering for connections to unusual or untrusted destinations.
*   Implement network-level detection rules to identify data exfiltration attempts based on traffic patterns, such as large data transfers or connections to known malicious IPs.
*   Regularly review and update GenAI application configurations to ensure they are securely configured and protected against unauthorized access.
*   Investigate any alerts triggered by this rule to determine the scope of the potential data exfiltration.
