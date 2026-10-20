---
brief_id: brief-2026-03-30-charlotte-ai-agentworks
event_id: brief-2026-03-30-charlotte-ai-agentworks
revision: 1
activity_at: "2026-03-28T09:22:10Z"
title: CrowdStrike Charlotte AI AgentWorks Fuels Agentic Security Ecosystem
slug: 2026-03-charlotte-ai-agentworks
description: CrowdStrike's Charlotte AI AgentWorks facilitates the creation and orchestration of AI-driven security agents within the SOC, aiming to enhance analyst capabilities and automate security operations using AI.
date: "2026-03-28T09:22:10Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
tags:
  - agentic-soc
  - ai
  - security-automation
references:
  - https://www.crowdstrike.com/en-us/blog/how-charlotte-ai-agentworks-fuels-securitys-agentic-ecosystem/
rules:
  - title: Detect PowerShell Execution with Suspicious Parameters
    description: Detects PowerShell execution with parameters commonly used by attackers, such as bypassing execution policy or hiding the console.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Network Connection from Uncommon Process
    description: Detects network connections initiated by processes that are not typically associated with network activity.
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

On March 25, 2026, CrowdStrike announced Charlotte AI AgentWorks, a platform designed to build and orchestrate AI-powered security agents. This platform aims to address the increasing speed and sophistication of cyberattacks, with eCrime breakout times as low as 27 seconds and a significant rise in AI-powered adversaries. Charlotte AI AgentWorks seeks to enable organizations to adopt an agentic security operations model, where analysts oversee context-aware AI agents that can automate tasks and enhance threat response. The goal is to augment human analysts rather than replace them, extending their expertise with machine-speed capabilities. Charlotte AI AgentWorks includes integrations with leading AI models from Anthropic, NVIDIA, and OpenAI, and AI infrastructure services such as Amazon Bedrock and Amazon SageMaker. Partners like Accenture, Deloitte, and Kroll are already using the platform to build custom agents.

## Attack Chain

This brief describes a platform for *defending* against attacks, not an actual attack chain. Therefore, this section describes the *intended use* of the platform in the context of typical attack stages.

1. **Initial Access Detection:** Agents monitor network traffic and endpoint activity for suspicious patterns indicative of initial access attempts, such as phishing or exploit activity.
2. **Execution Prevention:** AI-driven agents analyze processes and scripts executed on endpoints, identifying and blocking malicious code based on behavior and threat intelligence.
3. **Persistence Hunting:** Agents scan systems for persistence mechanisms like registry keys or scheduled tasks indicative of malware establishing a foothold.
4. **Privilege Escalation Monitoring:** Agents track process creation and API calls related to privilege escalation attempts, alerting on unusual or unauthorized activity.
5. **Lateral Movement Detection:** AI-powered agents analyze network connections and authentication events to detect anomalous lateral movement patterns within the network.
6. **Command and Control Blocking:** Agents identify and block communication with known command and control servers based on threat intelligence and behavioral analysis.
7. **Data Exfiltration Prevention:** Agents monitor network traffic and file access patterns to detect and prevent unauthorized data exfiltration attempts.

## Impact

The successful deployment of Charlotte AI AgentWorks can lead to a reduction in manual investigation workloads by 70%, restoring over 40 hours of team capacity per week, and achieving greater than 98% decision accuracy. This results in faster incident response times, improved threat detection rates, and a more efficient security operations center (SOC). Failure to adopt such AI-driven security measures could leave organizations vulnerable to increasingly sophisticated and rapid cyberattacks.

## Recommendation

*   Explore and experiment with Charlotte AI AgentWorks using the provided 50 free AI credits to understand its capabilities and potential benefits for your organization.
*   Leverage the twelve out-of-the-box agents offered by Charlotte Agentic SOAR for tasks like triage and malware analysis, as described in the overview, to automate common SOC workflows.
*   Integrate Charlotte AI AgentWorks with existing security tools and workflows to enhance threat detection and response capabilities as outlined in the overview.
*   Develop custom security agents using Charlotte AI AgentWorks and the available AI models and integrations to address specific security needs and challenges within your environment.
*   Utilize the unified case management features of Charlotte Agentic SOAR, mentioned in the overview, to streamline investigations, track resolution times, and identify operational bottlenecks.
