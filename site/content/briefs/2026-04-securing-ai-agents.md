---
title: Securing AI Agents and Governing Shadow AI
slug: 2026-04-securing-ai-agents
description: CrowdStrike is introducing new capabilities to secure AI agents and govern shadow AI across endpoints, SaaS, and cloud environments by providing detection and response (AIDR) for desktop AI applications, discovery of AI-related components, and runtime security for agents built in Microsoft Copilot Studio to combat attacks like living off the AI land (LOTAIL) by securing the agentic interaction layer.
date: "2026-03-30T06:41:52Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - AI
  - agentic-soc
  - shadow-ai
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
references:
  - https://crowdstrike.com/en-us/blog/new-crowdstrike-innovations-secure-ai-agents-govern-shadow-ai/
rules:
  - title: Detect AI Application Execution via Command Line
    description: Detects the execution of common AI applications like ChatGPT, Gemini, or Copilot via command line, which can be an indicator of malicious activity or unauthorized usage.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: AI Discovery Tool Execution
    description: Detects execution of an AI discovery tool, which is an initial step to identifying and classifying AI-related components such as LLMs and MCP servers. This execution might be benign, but in the wrong hands, could be used for reconnaissance.
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

Organizations are rapidly adopting AI tools, deploying AI agents, and building AI-powered software, which introduces new attack surfaces. These new surfaces are often unprotected by traditional security controls. This rapid adoption of AI has led to the rise of shadow AI, where employees adopt AI tools without oversight and engineering teams deploy models and agents without adequate visibility and runtime protection. CrowdStrike is releasing new innovations across their Falcon platform to extend AI detection and response (AIDR) capabilities to secure AI workforce adoption and development across endpoints, SaaS environments, and cloud environments. Specifically, CrowdStrike is providing AI Detection and Response for desktop AI applications like ChatGPT, Gemini, Claude, DeepSeek, Microsoft Copilot, O365 Copilot, GitHub Copilot, and Cursor. This will give security teams visibility into employees’ use of these AI apps, including full prompt content, and the ability to detect prompt attacks, data leaks, and access control and content policy violations.

## Attack Chain

1. An attacker gains initial access to an endpoint, potentially through social engineering or exploiting a software vulnerability (Initial Access).
2. The attacker leverages a personal AI agent like OpenClaw, taking advantage of its high system permissions and minimal governance, to execute terminal commands (Execution).
3. The AI agent is used to browse the web and interact with files on the system (Execution).
4. The attacker leverages the AI agent's capabilities to autonomously take actions that mimic legitimate user behavior, making detection difficult (Defense Evasion).
5. The AI agent is used to access sensitive data stored on the endpoint, such as credentials, intellectual property, or customer data (Credential Access, Discovery).
6. The AI agent is used to exfiltrate the stolen data to an external server controlled by the attacker (Exfiltration).
7. The attacker uses prompt injection techniques to manipulate AI agents to perform malicious actions (Execution).
8. The attacker gains access to sensitive data, intellectual property, or customer data, leading to financial loss, reputational damage, or regulatory fines (Impact).

## Impact

Successful exploitation of AI agents can lead to significant data breaches, exposing sensitive information like customer data, intellectual property, and financial records. The rise of "living off the AI land" (LOTAIL) techniques makes it harder to detect malicious activity, allowing attackers to remain undetected for longer periods. This can cause financial losses due to data breaches and reputational damage. The sectors most impacted are those heavily adopting AI, including technology, finance, and healthcare, though all sectors are potentially vulnerable.

## Recommendation

*   Deploy the Falcon AIDR browser extension from the Falcon console to monitor employee AI interactions and detect prompt attacks and data leaks across a range of AI tools on endpoints (AIDR Feature).
*   Utilize AI Discovery in CrowdStrike Falcon Exposure Management to identify AI-related components such as LLMs, Model Context Protocol (MCP) servers, and IDE extensions running across endpoints (Falcon Exposure Management).
*   Monitor Falcon AIDR alerts for suspicious activities related to Microsoft Copilot Studio agents, including prompt injection attacks, data leaks, and policy violations (Falcon AIDR).
