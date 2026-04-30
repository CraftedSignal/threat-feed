---
title: CrowdStrike Charlotte AI AgentWorks and Agentic SOAR for Agentic Security Operations
slug: 2024-07-charlotte-ai-agentworks
description: CrowdStrike's Charlotte AI AgentWorks and Agentic SOAR aim to revolutionize security operations by enabling the creation and orchestration of AI-powered agents, enhancing analyst capabilities and automating tasks to combat AI-accelerated adversaries.
date: "2026-03-28T08:31:25Z"
type: advisory
types:
  - advisory
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

CrowdStrike has introduced Charlotte AI AgentWorks and Charlotte Agentic SOAR as a foundation for agentic security operations. Charlotte AI AgentWorks is designed to be a central hub for building and scaling security agents, integrating frontier AI models from Anthropic, NVIDIA, and OpenAI. This platform enables partners and service providers like Accenture, Deloitte, Kroll, Telefonica Tech, and Salesforce to develop custom agents tailored for diverse teams and environments. Charlotte Agentic SOAR serves as the orchestration layer, activating and coordinating agents across complex workflows while maintaining human oversight and security guardrails. The goal is to amplify analyst capabilities, automate time-intensive tasks, and improve decision accuracy in the face of AI-powered adversaries.

## Attack Chain

1.  **Initial Compromise (Simulated):** An attacker attempts to leverage a vulnerability, triggering a security alert that requires immediate attention.
2.  **Agent Activation:** Charlotte Agentic SOAR automatically activates a malware analysis agent to examine suspicious files.
3.  **Data Analysis:** The malware analysis agent analyzes the file using integrated threat intelligence and AI models.
4.  **Threat Prioritization:** An exposure prioritization agent is engaged to identify and rank potential risks associated with the alert.
5.  **Workflow Automation:** Based on the agent's findings, automated workflows are initiated to contain the potential threat and alert relevant personnel.
6.  **Human Oversight:** Analysts review the agent's findings and the automated actions, providing oversight and making strategic decisions.
7.  **Remediation:** The security team uses the enriched data to quickly respond and remediate the threat.
8.  **Adaptive Security:** The entire process enhances the overall security posture by automating mundane tasks, allowing the analysts to focus on critical and complex issues, improving overall incident response time and accuracy.

## Impact

By leveraging Charlotte AI AgentWorks and Agentic SOAR, organizations can potentially reduce manual investigation workloads by up to 70%, restore approximately 40 hours of team capacity per week, and achieve decision accuracy exceeding 98%. This enhanced efficiency and precision can significantly improve an organization's ability to detect and respond to threats, minimizing the impact of successful attacks.

## Recommendation

*   Investigate the capabilities of Charlotte AI AgentWorks and Agentic SOAR to determine potential benefits for your security operations, referencing the CrowdStrike documentation available online ([https://www.crowdstrike.com/en-us/blog/how-charlotte-ai-agentworks-fuels-securitys-agentic-ecosystem/](https://www.crowdstrike.com/en-us/blog/how-charlotte-ai-agentworks-fuels-securitys-agentic-ecosystem/)).
*   Simulate the attack chain described to understand how different AI agents can aid in analysis and remediation.
*   Deploy a detection rule to identify anomalies in workflow automation engines.
