---
title: CrowdStrike Charlotte AI AgentWorks and Agentic SOAR
slug: 2026-03-charlotte-ai-agentworks
description: CrowdStrike's Charlotte AI AgentWorks aims to build and scale security agents across enterprises, integrating with AI models from Anthropic, NVIDIA, and OpenAI, while Charlotte Agentic SOAR operationalizes agentic defense with pre-built agents for tasks like malware analysis and triage, offering free AI credits to accelerate adoption.
date: "2026-03-30T06:19:01Z"
severities:
  - medium
tags:
  - agentic-soc
  - ai
  - soar
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
references:
  - https://www.crowdstrike.com/en-us/blog/how-charlotte-ai-agentworks-fuels-securitys-agentic-ecosystem/
rules:
  - title: Detect Suspicious Process interacting with AI Agents
    description: Detects processes interacting with AI AgentWorks or Agentic SOAR applications that may indicate unexpected agent behavior.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Outbound Connections from AI Agents
    description: Detects suspicious outbound network connections originating from hosts running AI Agents.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CrowdStrike's Charlotte AI AgentWorks, announced in March 2026, is designed to be a central hub for building and scaling security agents across enterprises. It integrates with frontier AI models from Anthropic, NVIDIA, and OpenAI, alongside AI infrastructure services such as Amazon Bedrock and Amazon SageMaker. Charlotte AI AgentWorks is designed to enable partners and service providers to build differentiated agentic security businesses on the Falcon platform. Charlotte Agentic SOAR is…
