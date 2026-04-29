---
title: CrowdStrike Charlotte AI AgentWorks and Agentic SOAR
slug: 2026-03-charlotte-ai
description: CrowdStrike's Charlotte AI AgentWorks and Agentic SOAR offer a security-first ecosystem for building and orchestrating AI agents across the SOC, enhancing automation and analyst capabilities, and offering free AI credits to accelerate customer adoption.
date: "2026-03-29T06:43:27Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - agentic-soc
  - ai
  - automation
references:
  - https://www.crowdstrike.com/en-us/blog/how-charlotte-ai-agentworks-fuels-securitys-agentic-ecosystem/
rules:
  - title: Detecting Potential Automation Tools Execution
    description: Detects the execution of potential automation tools that might be leveraged in an agentic SOC environment. This will detect unusual process creations.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - windows
  - title: Detecting Suspicious Outbound Network Connection
    description: Detects suspicious outbound network connections potentially related to automated agents. Monitor for unusual network connections.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CrowdStrike has introduced Charlotte AI AgentWorks and Charlotte Agentic SOAR, aimed at transforming security operations through the use of AI-powered security agents. Charlotte AI AgentWorks serves as a central hub for building and scaling these agents, integrating with leading AI models from Anthropic, NVIDIA, and OpenAI. This platform allows partners and service providers to build custom agents tailored for diverse enterprise environments. Charlotte Agentic SOAR orchestrates these agents within security workflows, enabling autonomous operations with built-in security guardrails, human oversight, and governed access. The goal is to augment security analysts by automating time-intensive tasks such as malware analysis and exposure prioritization, enhancing overall efficiency and decision accuracy. CrowdStrike is offering 50 free AI credits per month to customers to encourage adoption and experimentation with the platform.

## Attack Chain

This threat brief describes new product features, not an attack chain. Therefore, the attack chain is not applicable.

## Impact

The introduction of Charlotte AI AgentWorks and Agentic SOAR aims to reduce manual investigation workloads by 70% and restore more than 40 hours of team capacity per week. It also strives to achieve greater than 98% decision accuracy in security operations. Successful deployment of these technologies can significantly enhance the efficiency and effectiveness of security teams, providing an operating advantage in an environment increasingly dominated by AI-powered threats. The availability of free AI credits is intended to lower the barrier to entry for organizations looking to adopt AI-driven security measures.

## Recommendation

*   Monitor process creations for unexpected use of automation tools, as these may be leveraged to implement AI-driven actions (reference the provided Sigma rule for process creation).
*   Review network connection logs for unusual data flows as automated agents are deployed, as these could be indicative of malicious actors attempting to use these to exfiltrate data (reference the provided Sigma rule for network connections).
*   Evaluate the Falcon platform telemetry for unusual behavior that may arise from exploitation attempts targeting AI-driven security agents (reference: Falcon Platform).
