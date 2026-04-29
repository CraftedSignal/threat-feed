---
title: CrowdStrike Charlotte AI AgentWorks for Security Operations
slug: 2026-03-charlotte-ai
description: CrowdStrike's Charlotte AI AgentWorks aims to enhance security operations by providing a platform for building and orchestrating AI-powered security agents, integrating with leading AI models and offering features like mission-ready agents and workflow automation to improve analyst efficiency and decision accuracy.
date: "2026-03-30T06:24:43Z"
type: coverage
types:
  - coverage
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

CrowdStrike's Charlotte AI AgentWorks, announced in March 2026, is a platform designed to enable the development and deployment of AI-driven security agents within security operations centers (SOCs). It addresses the challenges posed by increasing attack speeds and AI-powered adversaries. AgentWorks integrates with frontier AI models from companies like Anthropic, NVIDIA, and OpenAI, offering secure model optionality. It also fosters a collaborative ecosystem, involving partners like Accenture, Deloitte, Kroll, and Salesforce, who are building custom agents on the Falcon platform. The platform aims to enhance analyst capabilities by automating tasks, improving decision-making, and streamlining workflows. Charlotte AI AgentWorks includes Charlotte Agentic SOAR, which provides an orchestration layer for managing and coordinating agents across various security tasks.

## Attack Chain

This brief describes a platform for *defending* against attacks. No attack chain is available.

## Impact

The successful deployment of Charlotte AI AgentWorks aims to reduce manual investigation workloads by 70%, restore more than 40 hours of team capacity per week, and achieve greater than 98% decision accuracy. By automating repetitive tasks and providing AI-driven insights, organizations can improve the efficiency and effectiveness of their security operations. The platform intends to fundamentally reshape the analyst experience by eliminating toil, accelerating outcomes, and helping teams gain an operating advantage in the AI era.

## Recommendation

*   Familiarize yourself with the capabilities of Charlotte AI AgentWorks to understand how AI-powered agents can augment security operations.
*   Evaluate the potential of integrating AgentWorks-built agents into existing security workflows to automate tasks and improve decision-making.
*   Monitor CrowdStrike Falcon platform telemetry for events related to the deployment and usage of Charlotte AI agents to ensure proper configuration and security guardrails.
*   Review and customize out-of-the-box agents provided with Charlotte Agentic SOAR to align with specific security requirements and operational processes.
*   Leverage the natural language processing capabilities of Charlotte AI to rapidly prototype and manage automated workflows.
