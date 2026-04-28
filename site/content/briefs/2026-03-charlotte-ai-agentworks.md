---
title: CrowdStrike Charlotte AI AgentWorks and Agentic SOAR for AI-Enhanced Security Operations
slug: 2026-03-Charlotte-AI-AgentWorks
description: CrowdStrike's Charlotte AI AgentWorks facilitates the creation and deployment of AI-driven security agents, orchestrated by Charlotte Agentic SOAR, to augment security analysts and accelerate threat response, offered with complimentary AI credits to encourage adoption.
date: "2026-03-29T06:58:32Z"
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

CrowdStrike has announced Charlotte AI AgentWorks and Charlotte Agentic SOAR to enhance security operations through AI-driven automation. Charlotte AI AgentWorks serves as a platform for building and scaling security agents, integrating with models from Anthropic, NVIDIA, and OpenAI. Charlotte Agentic SOAR acts as an orchestration layer, enabling users to activate and coordinate agents across complex workflows while maintaining human oversight. Launch partners include Accenture, Deloitte…
