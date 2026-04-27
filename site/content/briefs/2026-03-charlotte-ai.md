---
title: CrowdStrike Charlotte AI AgentWorks for Agentic SOC Transformation
slug: 2026-03-charlotte-ai
description: CrowdStrike's Charlotte AI AgentWorks facilitates the development and deployment of AI-driven security agents within the SOC, aiming to enhance analyst capabilities through automated and orchestrated responses to threats.
date: "2026-03-28T09:13:21Z"
severities:
  - medium
tags:
  - agentic-soc
  - ai-security
  - automation
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.crowdstrike.com/en-us/blog/how-charlotte-ai-agentworks-fuels-securitys-agentic-ecosystem/
rules:
  - title: Detect Suspicious PowerShell Encoded Command Execution
    description: Detects PowerShell execution with Base64 encoded commands, often used by attackers to evade detection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Scheduled Task Creation via Command Line
    description: Detects the creation of scheduled tasks via the command line, a common persistence technique.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike has introduced Charlotte AI AgentWorks, a platform designed to enable the development and orchestration of AI-powered security agents within the Security Operations Center (SOC). Launched in March 2026, the platform aims to shift analysts from manual firefighting to strategic oversight by automating tasks and enabling context-aware responses. Charlotte AI AgentWorks integrates with leading AI models from Anthropic, NVIDIA, and OpenAI, and provides twelve pre-built agents for tasks…
