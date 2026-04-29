---
title: CrowdStrike Charlotte AI AgentWorks and Agentic SOAR
slug: 2026-03-charlotte-ai-agentworks
description: CrowdStrike's Charlotte AI AgentWorks aims to build and scale security agents across enterprises, integrating with AI models from Anthropic, NVIDIA, and OpenAI, while Charlotte Agentic SOAR operationalizes agentic defense with pre-built agents for tasks like malware analysis and triage, offering free AI credits to accelerate adoption.
date: "2026-03-30T06:19:01Z"
type: coverage
types:
  - coverage
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

CrowdStrike's Charlotte AI AgentWorks, announced in March 2026, is designed to be a central hub for building and scaling security agents across enterprises. It integrates with frontier AI models from Anthropic, NVIDIA, and OpenAI, alongside AI infrastructure services such as Amazon Bedrock and Amazon SageMaker. Charlotte AI AgentWorks is designed to enable partners and service providers to build differentiated agentic security businesses on the Falcon platform. Charlotte Agentic SOAR is presented as the orchestration layer to activate and coordinate these agents across workflows. A key initiative is offering 50 free AI credits monthly to CrowdStrike customers to encourage experimentation with agentic operations.

## Attack Chain

This document describes a product, not an attack chain, so the below describes how the *product* functions, not how an attacker behaves.

1. **Agent Building:** Security teams or partners use Charlotte AI AgentWorks to build custom security agents, leveraging integrations with AI models from Anthropic, NVIDIA, and OpenAI.
2. **Integration with Falcon Platform:** Agents are built on the CrowdStrike Falcon platform, inheriting unified data, threat intelligence, and security guardrails.
3. **Workflow Design:** Users design workflows within Charlotte Agentic SOAR, defining triggers, selecting agents, establishing authorization checks, and setting automated actions.
4. **Agent Deployment:** Agents are deployed to address specific security tasks, such as triage, malware analysis, exposure prioritization, and correlation rule generation.
5. **Data Analysis:** Agents analyze telemetry from the Falcon platform to perform their assigned tasks, potentially reducing manual investigation workloads.
6. **Action Execution:** Agents execute automated actions based on their analysis, automating tasks that would otherwise require manual intervention.
7. **Human Oversight:** Charlotte Agentic SOAR provides mechanisms for human oversight, ensuring governed access and bounded autonomy for the deployed agents.

## Impact

If adopted successfully, organizations could see a reduction in manual investigation workloads by 70%, restore more than 40 hours of team capacity per week, and achieve greater than 98% decision accuracy. This aims to fundamentally reshape the analyst experience by eliminating toil, accelerating outcomes, and helping teams seize an operating advantage in the AI era. A failure to properly secure and manage these AI agents could lead to unintended actions, data breaches, or other security incidents.

## Recommendation

*   Monitor process creation events for processes interacting with the Charlotte AI AgentWorks and Agentic SOAR applications to identify unexpected agent behavior (Logsource: `process_creation`, Rule: "Detect Suspicious Process interacting with AI Agents").
*   Review network connections originating from hosts running Charlotte AI AgentWorks and Agentic SOAR applications, focusing on connections to unexpected or untrusted destinations (Logsource: `network_connection`, Rule: "Detect Suspicious Outbound Connections from AI Agents").
*   Enable logging and alerting for configuration changes within Charlotte AI AgentWorks and Agentic SOAR to detect unauthorized modifications to agent behavior or workflows (Logsource: Vendor-specific application logs, depending on implementation).
