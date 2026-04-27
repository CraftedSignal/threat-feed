---
title: CrowdStrike Charlotte AI AgentWorks for Security Operations
slug: 2026-03-charlotte-ai
description: CrowdStrike's Charlotte AI AgentWorks aims to enhance security operations by providing a platform for building and orchestrating AI-powered security agents, integrating with leading AI models and offering features like mission-ready agents and workflow automation to improve analyst efficiency and decision accuracy.
date: "2026-03-30T06:24:43Z"
severities:
  - medium
tags:
  - agentic-soc
  - ai
  - security-operations
references:
  - https://www.crowdstrike.com/en-us/blog/how-charlotte-ai-agentworks-fuels-securitys-agentic-ecosystem/
rules:
  - title: Detect Potential Charlotte AI Agent Activity
    description: Detects processes potentially related to Charlotte AI agents based on image name.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
  - title: Detect Charlotte AI SOAR Workflow Execution
    description: Detects execution of workflows within Charlotte AI Agentic SOAR based on command line arguments.
    platform: sigma
    severity: low
    tactics:
      - execution
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike's Charlotte AI AgentWorks, announced in March 2026, is a platform designed to enable the development and deployment of AI-driven security agents within security operations centers (SOCs). It addresses the challenges posed by increasing attack speeds and AI-powered adversaries. AgentWorks integrates with frontier AI models from companies like Anthropic, NVIDIA, and OpenAI, offering secure model optionality. It also fosters a collaborative ecosystem, involving partners like Accenture…
