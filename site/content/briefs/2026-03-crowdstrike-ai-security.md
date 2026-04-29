---
title: CrowdStrike Enhancements to Secure AI Agents and Govern Shadow AI
slug: 2026-03-crowdstrike-ai-security
description: CrowdStrike is releasing new capabilities to extend AI detection and response (AIDR) across endpoints, SaaS, and cloud environments to address the growing attack surface presented by AI agents and shadow AI adoption, including techniques like 'Living Off The AI Land' (LOTAIL).
date: "2026-03-23T09:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - AI-security
  - shadow-ai
  - LOTAIL
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1199
    technique_name: Trusted Relationship
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://www.crowdstrike.com/en-us/blog/new-crowdstrike-innovations-secure-ai-agents-govern-shadow-ai/
rules:
  - title: Detect Suspicious AI Application Process Creation
    description: Detects the creation of processes associated with AI applications like ChatGPT, Gemini, and Microsoft Copilot, which could indicate malicious activity or unauthorized usage.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1199
    data_sources:
      - process_creation
      - windows
  - title: Detect AI Agent Discovery Activity
    description: Detects potential AI agent discovery attempts based on command-line arguments
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

CrowdStrike is enhancing its Falcon platform to address the emerging threats associated with the increasing adoption of AI agents and shadow AI within organizations. This update focuses on securing AI workforce adoption and development across endpoints, SaaS environments, and cloud infrastructures. With the rise of personal AI agents, a new attack surface is created, leading to techniques like "Living Off The AI Land" (LOTAIL), where adversaries exploit AI agents for malicious purposes. The Falcon AIDR's runtime threat detection capabilities are extended beyond browsers to cover desktop AI applications such as ChatGPT, Gemini, and Microsoft Copilot. Additionally, the AI Discovery feature in CrowdStrike Falcon Exposure Management identifies AI-related components running across endpoints, including LLMs and IDE extensions, providing improved visibility and risk assessment. These enhancements aim to close the AI visibility and governance gap, enabling organizations to confidently accelerate AI development and adoption.

## Attack Chain

1.  Initial Access: An attacker gains initial access to a developer's machine, potentially through compromised credentials or a supply chain attack targeting an IDE extension.
2.  Agent Deployment: The developer unknowingly deploys a malicious AI agent or extension onto their endpoint, granting the attacker a foothold.
3.  LOTAIL Execution: The attacker utilizes the compromised AI agent to perform actions on the system, blending in with legitimate user behavior and bypassing traditional security controls.
4.  Data Exfiltration: The AI agent is used to access and exfiltrate sensitive data, such as source code, API keys, or customer information.
5.  Lateral Movement: The attacker leverages the compromised agent to gain access to other systems or resources within the network, escalating their privileges and expanding their reach.
6.  Policy Violation: The malicious AI agent violates established data access and content policies, potentially leading to data leaks or unauthorized access to sensitive information.
7.  Compromise of AI Models: The attacker targets and compromises locally hosted Large Language Models (LLMs) or Model Context Protocol (MCP) servers, gaining control over AI models.
8.  Impact: The attacker achieves their objective, whether it's data theft, intellectual property compromise, or disruption of business operations, by leveraging the compromised AI agents and infrastructure.

## Impact

The successful exploitation of AI agents and shadow AI can lead to significant data breaches, intellectual property theft, and disruption of business operations. The lack of visibility and governance over AI deployments creates a blind spot for security teams, allowing attackers to operate undetected. The consequences can range from financial losses and reputational damage to regulatory fines and legal liabilities. The convergence of increased agent autonomy, high system permissions, and minimal governance on endpoints exacerbates the risk, making it crucial for organizations to implement robust AI security measures.

## Recommendation

*   Deploy Falcon AIDR to gain visibility into employee use of AI applications on endpoints, including full prompt content (reference: Falcon AIDR).
*   Utilize AI Discovery in CrowdStrike Falcon® Exposure Management to identify and classify AI-related components running across endpoints in real time, including AI apps and LLM runtimes (reference: AI Discovery in CrowdStrike Falcon® Exposure Management).
*   Implement Falcon AIDR policies to monitor and detect prompt injection attacks, data leaks, and policy violations in real-time for Copilot Studio agents (reference: Falcon AIDR for Copilot Studio Agents).
*   Enable Sysmon process creation logging to improve visibility into newly created AI processes on endpoints and aid in the tuning of detection rules.
*   Monitor network connections for AI applications, specifically those using unconventional ports or communicating with untrusted external endpoints.
*   Deploy the Sigma rules below to your SIEM to detect suspicious AI-related activity.
