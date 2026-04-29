---
title: CrowdStrike Innovations Secure AI Agents and Govern Shadow AI
slug: 2026-03-shadow-ai-governance
description: CrowdStrike is introducing innovations to secure AI agents and govern shadow AI across endpoints, SaaS, and cloud environments by extending AI detection and response (AIDR) capabilities to cover desktop AI applications and provide visibility into AI-related components, helping to prevent prompt attacks, data leaks, and policy violations.
date: "2026-03-28T21:52:45Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - AI
  - AI-Security
  - Shadow-AI
  - Endpoint-Security
  - SaaS
  - Cloud
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
references:
  - https://www.crowdstrike.com/en-us/blog/new-crowdstrike-innovations-secure-ai-agents-govern-shadow-ai/
rules:
  - title: AI Desktop Application Usage Detected
    description: Detects the execution of common AI desktop applications.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - process_creation
      - windows
  - title: Potential AI Related Process Discovery
    description: Detects processes that are potentially related to AI models
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike is addressing the emerging threat landscape created by the rapid adoption of AI tools and agents within organizations. The increasing use of personal AI agents, particularly on developer machines, introduces new attack vectors such as "living off the AI land" (LOTAIL) exploits, indirect prompt injection, and agentic tool chain attacks. The rise of shadow AI, where employees adopt AI tools without oversight, exacerbates the issue. CrowdStrike's new innovations extend AI Detection and Response (AIDR) capabilities to cover desktop AI applications (ChatGPT, Gemini, Claude, DeepSeek, Microsoft Copilot, O365 Copilot, GitHub Copilot, and Cursor) and expand platform capabilities to secure AI workforce adoption and development across endpoints, SaaS environments, and cloud environments. Falcon AIDR will leverage the Falcon sensor to enable deployment of the Falcon AIDR browser extension from the Falcon console and obtain desktop application telemetry via the sensor's container network interface capability.

## Attack Chain

1.  **Initial Access (via AI Agent):** An attacker gains initial access by compromising an AI agent running on an endpoint, potentially through prompt injection or other vulnerabilities in the agent's design.
2.  **Privilege Escalation:** The attacker leverages the compromised AI agent's existing system permissions, which may be elevated, to gain further access to the system. AI agents often have high privileges to execute terminal commands, browse the web, and interact with files.
3.  **Living off the AI Land (LOTAIL):** The attacker uses the compromised AI agent to perform malicious actions that appear as legitimate user behavior, such as executing terminal commands, browsing websites, or interacting with files.
4.  **Lateral Movement:** The attacker utilizes the AI agent's network connectivity to discover and access other systems within the network, including LLM runtimes, MCP servers, and IDE extensions.
5.  **Data Exfiltration:** The attacker uses the AI agent to exfiltrate sensitive data from the compromised systems, such as source code, credentials, or other confidential information.
6.  **Supply Chain Compromise:** The attacker uses access to development environments via compromised AI tools to introduce malicious code into the software supply chain.
7.  **Policy Violation:** The attacker manipulates the AI agent to violate content policies or access control rules, potentially leading to unauthorized access to sensitive data or systems.

## Impact

Successful attacks targeting AI agents and shadow AI can lead to significant data breaches, intellectual property theft, and supply chain compromises. The lack of visibility and governance over AI deployments creates a growing attack surface that traditional security controls are ill-equipped to handle. Compromised AI agents can be used to perform a wide range of malicious activities, including data exfiltration, lateral movement, and the introduction of malicious code into the software supply chain. The impact can range from financial losses and reputational damage to the compromise of critical infrastructure and sensitive government systems.

## Recommendation

*   Deploy the Sigma rule "AI Desktop Application Usage Detected" to identify and monitor the use of AI desktop applications such as ChatGPT, Gemini, and others within your environment. This rule uses `process_creation` logs to detect the execution of these applications (see rule below).
*   Enable and configure AI Discovery in CrowdStrike Falcon Exposure Management to gain visibility into AI-related components running across endpoints, including AI apps, LLM runtimes, MCP servers, and IDE extensions. This leverages `Falcon for IT` telemetry as described in the overview.
*   Implement Falcon AIDR policies to monitor and protect agents built in Microsoft Copilot Studio against prompt injection attacks, data leaks, and policy violations.
*   Review and update access control policies for AI agents to minimize the potential impact of a compromise, focusing on the principle of least privilege.
