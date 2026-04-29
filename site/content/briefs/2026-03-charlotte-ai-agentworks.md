---
title: CrowdStrike Charlotte AI AgentWorks and Agentic SOAR for Automated Security Operations
slug: 2026-03-charlotte-ai-agentworks
description: CrowdStrike introduces Charlotte AI AgentWorks and Agentic SOAR to enhance security operations through AI-driven automation and orchestration, reducing manual workloads and improving decision accuracy.
date: "2026-03-28T09:22:10Z"
type: coverage
types:
  - coverage
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

CrowdStrike is introducing Charlotte AI AgentWorks and Agentic SOAR as a new approach to security operations, designed to leverage AI to automate tasks, orchestrate workflows, and amplify analyst capabilities. Announced in March 2026, Charlotte AI AgentWorks serves as a central hub for building and scaling security agents across the enterprise, integrating with models from Anthropic, NVIDIA, and OpenAI, and promoting collaboration among security innovators. Charlotte Agentic SOAR is designed to enable the coordinated operation of these agents within complex security workflows, providing mission-ready agents for common tasks like triage and malware analysis. The aim is to reduce manual workloads, enhance decision-making accuracy, and provide a security-first foundation for AI-driven automation. To help customers accelerate AI adoption, CrowdStrike offers free AI credits for experimentation within their environments.

## Attack Chain

This brief describes new product capabilities and not an active attack chain. Therefore, a typical attack chain is not applicable. However, the following steps outline how a security team might leverage the capabilities:

1.  **AI Model Integration:** The organization integrates various AI models from providers like Anthropic, NVIDIA, and OpenAI into the Charlotte AI AgentWorks platform, choosing the most suitable models for specific security tasks.
2.  **Agent Development:** Security engineers use Charlotte AI AgentWorks to develop custom security agents tailored to their environment, leveraging the platform's tools and frameworks.
3.  **Workflow Design:** Using Charlotte Agentic SOAR, analysts design automated workflows that incorporate the newly created and out-of-the-box agents to address specific security challenges, such as threat triage or malware analysis.
4.  **Agent Deployment:** The security agents are deployed across the CrowdStrike Falcon platform, inheriting the platform's telemetry, security guardrails, and access controls.
5.  **Task Automation:** The agents automatically perform tasks such as triaging alerts, analyzing malware samples, prioritizing exposure management, and generating correlation rules.
6.  **Human Oversight:** Analysts monitor the agents' activities through the unified case management interface, ensuring that actions align with established security policies and compliance requirements.
7.  **Workflow Optimization:** The security team identifies operational bottlenecks and streamlines investigations based on the data provided by the case management system, continuously improving the automated workflows.
8.  **Analyst Amplification:** Analysts leverage the AI-driven automation to reduce manual tasks, accelerate response times, and focus on strategic oversight and complex investigations.

## Impact

Successful implementation of Charlotte AI AgentWorks and Agentic SOAR can lead to a significant reduction in manual investigation workloads, potentially by as much as 70%, and a restoration of over 40 hours of team capacity per week. The platform aims to achieve greater than 98% decision accuracy in automated tasks. By automating repetitive and time-consuming processes, organizations can free up security analysts to focus on more strategic initiatives, improving overall security posture and reducing the risk of successful attacks. The platform's goal is to reshape the analyst experience, eliminate toil, accelerate outcomes, and help teams seize an operating advantage in the AI era.

## Recommendation

*   Explore the capabilities of Charlotte AI AgentWorks and Agentic SOAR within a test environment using the free AI credits offered by CrowdStrike, to evaluate the potential benefits for your organization (Charlotte AI AgentWorks, Agentic SOAR).
*   Leverage the out-of-the-box agents available in Charlotte Agentic SOAR to automate common security tasks such as threat triage and malware analysis, and customize them to your environment (Charlotte Agentic SOAR).
*   Evaluate existing security workflows and identify areas where AI-driven automation can reduce manual effort and improve decision accuracy, designing new workflows using Charlotte Agentic SOAR (Charlotte Agentic SOAR).
*   Monitor the performance of deployed agents and automated workflows through the unified case management interface, identifying and addressing any bottlenecks or areas for optimization (Charlotte Agentic SOAR).
