---
title: CrowdStrike Charlotte AI AgentWorks and Agentic SOAR for Automated Security Operations
slug: 2026-03-charlotte-ai-agentworks
description: CrowdStrike introduces Charlotte AI AgentWorks and Agentic SOAR to enhance security operations through AI-driven automation and orchestration, reducing manual workloads and improving decision accuracy.
date: "2026-03-28T09:22:10Z"
severities:
  - medium
tags:
  - ai
  - automation
  - security operations
  - soar
references:
  - https://www.crowdstrike.com/en-us/blog/how-charlotte-ai-agentworks-fuels-securitys-agentic-ecosystem/
rules:
  - title: Detect Charlotte AI AgentWorks Agent Execution
    description: Detects execution of agents within the Charlotte AI AgentWorks framework based on process names.
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - process_creation
      - windows
  - title: Detect SOAR Workflow Modification
    description: Detects modifications to SOAR workflows, potentially indicating unauthorized changes.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1547
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CrowdStrike is introducing Charlotte AI AgentWorks and Agentic SOAR as a new approach to security operations, designed to leverage AI to automate tasks, orchestrate workflows, and amplify analyst capabilities. Announced in March 2026, Charlotte AI AgentWorks serves as a central hub for building and scaling security agents across the enterprise, integrating with models from Anthropic, NVIDIA, and OpenAI, and promoting collaboration among security innovators. Charlotte Agentic SOAR is designed to…
