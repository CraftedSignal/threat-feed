---
brief_id: brief-2026-03-29-charlotte-ai
event_id: brief-2026-03-29-charlotte-ai
revision: 2
activity_at: "2026-03-29T07:19:13Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:91a4721af314dc720499a76f6b6e298f1c780421767c8d4ac6751850e2551f5c
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: CrowdStrike Charlotte AI AgentWorks and Agentic SOAR for Agentic SOC
slug: 2026-03-29-charlotte-ai
description: CrowdStrike introduces Charlotte AI AgentWorks and Agentic SOAR to enable agentic security operations, leveraging AI and automation to enhance SOC capabilities by orchestrating context-aware agents that can reason across domains and take governed actions.
date: "2026-03-29T07:19:13Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
tags:
  - agentic-soc
  - ai-security
  - automation
references:
  - https://www.crowdstrike.com/en-us/blog/how-charlotte-ai-agentworks-fuels-securitys-agentic-ecosystem/
rules:
  - title: Detect Suspicious Agentic SOAR Workflow Modification
    description: Detects attempts to modify or inject malicious code into automated workflows managed by Charlotte Agentic SOAR.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1564
    data_sources:
      - file_event
      - windows
  - title: Detect Unauthorized Agent Invocation
    description: Detects processes attempting to invoke or control agents outside of authorized workflows.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike has launched Charlotte AI AgentWorks and Charlotte Agentic SOAR to address the challenges of modern security operations centers (SOCs) facing AI-accelerated adversaries. With eCrime breakout times decreasing to as fast as 27 seconds and AI-powered attacks increasing by 89% year-over-year, traditional SOC processes are no longer sufficient. Charlotte AI AgentWorks serves as a central hub for building and scaling security agents, integrating with AI models from Anthropic, NVIDIA, and OpenAI. Charlotte Agentic SOAR orchestrates these agents, automating tasks and streamlining workflows within a secure framework. Key partners like Accenture, Deloitte, Kroll, Telefonica Tech, and Salesforce are already leveraging Charlotte AI AgentWorks. CrowdStrike offers 50 free AI credits monthly to help customers accelerate AI adoption.

## Attack Chain

Given that the source material describes a product announcement and not an actual attack, the following attack chain is a hypothetical example of how an attacker might attempt to subvert an Agentic SOC environment:

1.  **Initial Compromise:** An attacker gains initial access to a system within the monitored environment, potentially through a phishing attack (T1566) or exploiting a known vulnerability (T1190).
2.  **Lateral Movement:** The attacker leverages compromised credentials or exploits vulnerabilities to move laterally within the network (T1021), attempting to gain access to systems that interact with the Agentic SOAR platform.
3.  **Agent Identification:** The attacker identifies available agents and their functionalities within the Charlotte AI AgentWorks ecosystem, looking for opportunities to manipulate or control them.
4.  **Workflow Manipulation:** The attacker attempts to modify or inject malicious code into automated workflows managed by Charlotte Agentic SOAR, aiming to disrupt operations or exfiltrate sensitive data (T1564).
5.  **Data Exfiltration:** If successful in manipulating workflows, the attacker uses the compromised agents to exfiltrate sensitive data (T1041) from the environment, potentially leveraging the agent's access to various data sources.
6.  **Privilege Escalation:** The attacker leverages the compromised agents or workflows to escalate privileges (T1068) within the system, gaining control over critical infrastructure.
7.  **System Disruption:** The attacker uses the compromised agents and elevated privileges to disrupt normal system operations (T1485), potentially leading to data loss, service outages, or ransomware deployment.

## Impact

A successful attack against an Agentic SOC environment could lead to significant data breaches, service disruptions, and financial losses. Since Charlotte AI AgentWorks aims to secure various enterprise environments, a successful compromise could impact numerous organizations relying on this technology. The potential for data exfiltration, system disruption, and reputational damage is high, given the reliance on AI-driven automation and orchestration. Organizations could experience a 70% reduction in manual investigation workloads as previously mentioned by CrowdStrike, but this advantage would be lost if agents are manipulated.

## Recommendation

*   Monitor process creation events for unauthorized or unexpected processes interacting with Charlotte AI AgentWorks or Charlotte Agentic SOAR binaries and directories using a rule such as the example provided for process_creation.
*   Implement strict access controls and multi-factor authentication for all users and services interacting with the Agentic SOC platform.
*   Regularly review and audit automated workflows within Charlotte Agentic SOAR to identify and mitigate any potential vulnerabilities or malicious code injections.
*   Monitor network connections for unusual or unauthorized traffic originating from or destined for systems hosting Charlotte AI AgentWorks or Charlotte Agentic SOAR using a rule such as the example provided for network_connection.
*   Deploy and tune the provided Sigma rules to detect suspicious activity related to agent manipulation or workflow compromise within the Agentic SOC environment.
