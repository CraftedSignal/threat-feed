---
title: CrowdStrike Charlotte AI AgentWorks and Agentic SOAR for Agentic Security Operations
slug: 2024-07-charlotte-ai-agentworks
description: CrowdStrike's Charlotte AI AgentWorks and Agentic SOAR aim to revolutionize security operations by enabling the creation and orchestration of AI-powered agents, enhancing analyst capabilities and automating tasks to combat AI-accelerated adversaries.
date: "2026-03-28T08:31:25Z"
severities:
  - medium
tags:
  - agentic-soc
  - ai
  - security-automation
references:
  - https://www.crowdstrike.com/en-us/blog/how-charlotte-ai-agentworks-fuels-securitys-agentic-ecosystem/
rules:
  - title: Detect Workflow Automation Engine Anomalies
    description: Detects unusual activity in workflow automation engines that may indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious File Analysis Agent
    description: Detects invocations of suspicious or custom file analysis agents.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike has introduced Charlotte AI AgentWorks and Charlotte Agentic SOAR as a foundation for agentic security operations. Charlotte AI AgentWorks is designed to be a central hub for building and scaling security agents, integrating frontier AI models from Anthropic, NVIDIA, and OpenAI. This platform enables partners and service providers like Accenture, Deloitte, Kroll, Telefonica Tech, and Salesforce to develop custom agents tailored for diverse teams and environments. Charlotte Agentic…
