---
title: CrowdStrike Falcon Enhancements for AI Agent Security and Shadow AI Governance
slug: 2026-03-ai-security
description: CrowdStrike is enhancing its Falcon platform to secure AI agents and govern shadow AI across endpoints, SaaS, and cloud environments, providing new detection and response capabilities for desktop AI applications, AI component discovery, and runtime security for Copilot Studio agents.
date: "2026-03-23T00:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - ai-security
  - shadow-ai
  - agentic-soc
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://crowdstrike.com/en-us/blog/new-crowdstrike-innovations-secure-ai-agents-govern-shadow-ai/
rules:
  - title: Detect AI Application Execution on Endpoint
    description: Detects the execution of known AI applications on endpoints, providing visibility into their usage.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - process_creation
      - windows
  - title: Detect AI Related Network Connection
    description: Detects the network connection related to AI application by filtering with process and destiantion address
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CrowdStrike is addressing the emerging attack surface created by the rapid adoption of AI tools and AI agents within organizations. The Falcon platform is being enhanced to provide visibility, governance, and runtime protection for AI across endpoints, SaaS, and cloud environments. This includes addressing novel threats such as indirect prompt injection and agentic tool chain attacks. The rise of shadow AI, where employees and engineering teams deploy AI tools without adequate oversight, is exacerbating the challenge, leading to an AI visibility and governance gap. These innovations aim to secure AI workforce adoption and AI development. Specific AI applications mentioned include ChatGPT, Gemini, Claude, DeepSeek, Microsoft Copilot, O365 Copilot, GitHub Copilot, and Cursor. The new features are rolling out across the Falcon platform with some in pre-beta and expected to reach general availability in Q2.

## Attack Chain

1.  An employee downloads and installs an unsanctioned AI application, such as a desktop AI tool like ChatGPT, on their endpoint, potentially bypassing traditional security controls.
2.  The AI application gains access to sensitive data or internal systems due to over-permissioning or misconfiguration.
3.  An attacker exploits a vulnerability in the AI application or its dependencies, gaining initial access to the endpoint.
4.  The attacker leverages "Living off the AI Land" (LOTAIL) techniques to blend malicious activity with legitimate AI agent behavior.
5.  The compromised AI agent executes commands or interacts with files, exfiltrating sensitive data from the endpoint or internal network.
6.  The attacker uses the AI agent to perform lateral movement, accessing other systems or data within the organization's environment.
7.  The attacker uses the compromised AI agent to perform prompt injection attacks against other AI systems or users.
8.  The final objective is data exfiltration and/or unauthorized access to critical systems, leading to potential financial loss, reputational damage, or intellectual property theft.

## Impact

The increasing use of AI tools and agents creates new attack surfaces that traditional security controls are not designed to protect.  Compromised AI agents can lead to data leaks, unauthorized access to sensitive systems, and lateral movement within the network.  The lack of visibility and governance over shadow AI deployments increases the risk of exploitation.  Successful attacks can result in significant financial losses, reputational damage, and intellectual property theft. While specific victim counts are not mentioned, the report emphasizes the broad potential impact across organizations adopting AI.

## Recommendation

*   Deploy the CrowdStrike Falcon AIDR to gain visibility and detect threats related to desktop AI applications, leveraging its runtime threat detection capabilities for workforce AI adoption.
*   Utilize Falcon Exposure Management's AI Discovery feature to automatically identify and classify AI-related components running across endpoints, including AI apps, LLM runtimes, and MCP servers.
*   Implement Falcon AIDR's security guardrails for agents built in Microsoft Copilot Studio to monitor for prompt injection attacks, data leaks, and policy violations in real-time.
*   Review and update existing security policies to address the risks associated with AI agent autonomy, system permissions, and shadow AI deployments.
*   Leverage Falcon for IT telemetry to enhance the visibility of the AI components and understand their connectivity to the rest of the environment.
