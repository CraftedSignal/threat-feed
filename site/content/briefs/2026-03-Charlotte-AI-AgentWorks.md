---
title: CrowdStrike Charlotte AI AgentWorks and Agentic SOAR for AI-Enhanced Security Operations
slug: 2026-03-Charlotte-AI-AgentWorks
description: CrowdStrike's Charlotte AI AgentWorks facilitates the creation and deployment of AI-driven security agents, orchestrated by Charlotte Agentic SOAR, to augment security analysts and accelerate threat response, offered with complimentary AI credits to encourage adoption.
date: "2026-03-29T06:58:32Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - agentic-soc
  - ai
  - security-automation
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
references:
  - https://www.crowdstrike.com/en-us/blog/how-charlotte-ai-agentworks-fuels-securitys-agentic-ecosystem/
rules:
  - title: Detect PowerShell Obfuscation with Base64 Encoding
    description: Detects PowerShell commands employing Base64 encoding for obfuscation, a common technique used by attackers to conceal malicious code.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Scheduled Task Creation
    description: Detects the creation of scheduled tasks that may be used for persistence by attackers.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
  - title: Detect Lateral Movement via Pass-The-Hash
    description: Detects potential pass-the-hash attacks by monitoring for authentication events with specific characteristics indicative of stolen credentials.
    platform: sigma
    severity: high
    tactics:
      - lateral_movement
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

CrowdStrike has announced Charlotte AI AgentWorks and Charlotte Agentic SOAR to enhance security operations through AI-driven automation. Charlotte AI AgentWorks serves as a platform for building and scaling security agents, integrating with models from Anthropic, NVIDIA, and OpenAI. Charlotte Agentic SOAR acts as an orchestration layer, enabling users to activate and coordinate agents across complex workflows while maintaining human oversight. Launch partners include Accenture, Deloitte, Kroll, Telefonica Tech, and Salesforce. The goal is to augment human analysts by automating routine tasks, speeding up response times, and improving accuracy in threat detection and analysis, especially against AI-powered adversaries. CrowdStrike offers 50 free AI credits monthly to encourage users to explore agentic operations within their environments.

## Attack Chain

While the provided document focuses on defensive technologies and not specific attacks, an attack chain for exploiting a system lacking such agentic security operations could look like this:

1. Initial Access: An attacker gains initial access through a phishing email containing a malicious attachment or link. (T1566.001)
2. Execution: The user opens the attachment, executing a malicious script (e.g., PowerShell) that bypasses initial security checks. (T1059.001)
3. Persistence: The script establishes persistence by creating a scheduled task or modifying a registry key to run the malicious code upon system startup. (T1053.005, T1547.001)
4. Privilege Escalation: The attacker exploits a known vulnerability or uses built-in tools to elevate privileges to gain administrator access. (T1068)
5. Lateral Movement: Using compromised credentials or pass-the-hash techniques, the attacker moves laterally to other systems within the network. (T1021.002)
6. Data Exfiltration: The attacker identifies and collects sensitive data, then compresses and encrypts it before exfiltrating it to an external server. (T1567.002, T1041)
7. Impact: The attacker deploys ransomware across the network, encrypting critical files and demanding a ransom payment for decryption. (T1486)

## Impact

Without agentic security operations, organizations face challenges in defending against rapidly evolving threats, particularly those leveraging AI. The document states that eCrime breakout times have collapsed to as fast as 27 seconds, and attacks from AI-powered adversaries have increased 89% year-over-year. Manual processes and fragmented tools can lead to slower response times, increased investigation workloads, and reduced decision accuracy. This can result in data breaches, financial losses, reputational damage, and business disruption. The goal of agentic security operations is to mitigate these risks and give defenders an operating advantage in the AI era.

## Recommendation

*   Evaluate CrowdStrike's Charlotte AI AgentWorks and Charlotte Agentic SOAR to determine their potential for automating security tasks and augmenting analyst capabilities.
*   Utilize the 50 free AI credits offered by CrowdStrike to experiment with agentic operations and assess their impact on your environment.
*   Assess your organization's current security operations model and identify areas where AI-driven automation can improve efficiency and effectiveness.
*   Consider integrating CrowdStrike-native, AgentWorks-built, and trusted third-party agents into your security workflows for coordinated defense.
*   Enable and monitor relevant log sources (e.g., process_creation, network_connection, file_event) to gain visibility into potential threats and the activities of AI-powered agents.
