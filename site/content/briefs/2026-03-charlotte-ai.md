---
title: CrowdStrike Charlotte AI AgentWorks and Agentic SOAR
slug: 2026-03-charlotte-ai
description: CrowdStrike's Charlotte AI AgentWorks and Agentic SOAR offer a security-first ecosystem for building and orchestrating AI agents across the SOC, enhancing automation and analyst capabilities, and offering free AI credits to accelerate customer adoption.
date: "2026-03-29T06:43:27Z"
severities:
  - medium
tags:
  - agentic-soc
  - ai
  - automation
references:
  - https://www.crowdstrike.com/en-us/blog/how-charlotte-ai-agentworks-fuels-securitys-agentic-ecosystem/
rules:
  - title: Detecting Potential Automation Tools Execution
    description: Detects the execution of potential automation tools that might be leveraged in an agentic SOC environment. This will detect unusual process creations.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - windows
  - title: Detecting Suspicious Outbound Network Connection
    description: Detects suspicious outbound network connections potentially related to automated agents. Monitor for unusual network connections.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CrowdStrike has introduced Charlotte AI AgentWorks and Charlotte Agentic SOAR, aimed at transforming security operations through the use of AI-powered security agents. Charlotte AI AgentWorks serves as a central hub for building and scaling these agents, integrating with leading AI models from Anthropic, NVIDIA, and OpenAI. This platform allows partners and service providers to build custom agents tailored for diverse enterprise environments. Charlotte Agentic SOAR orchestrates these agents…
