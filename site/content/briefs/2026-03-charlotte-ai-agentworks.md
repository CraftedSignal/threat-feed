---
title: CrowdStrike Charlotte AI AgentWorks and Agentic SOAR for Enhanced Security Operations
slug: 2026-03-charlotte-ai-agentworks
description: CrowdStrike's Charlotte AI AgentWorks and Agentic SOAR aim to improve security operations by enabling AI-powered autonomous agents, orchestrated to amplify analyst capabilities and automate tasks like malware analysis and exposure prioritization, reducing manual workloads and increasing decision accuracy.
date: "2026-03-28T08:17:38Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - agentic-soc
  - ai
  - soar
  - security-automation
references:
  - https://www.crowdstrike.com/en-us/blog/how-charlotte-ai-agentworks-fuels-securitys-agentic-ecosystem/
rules:
  - title: Detect Suspicious PowerShell Encoded Commands via Charlotte AI
    description: Detects PowerShell commands that contain Base64 encoded strings, which are often used to obfuscate malicious code. This rule helps identify potential exploitation attempts within the monitored environment.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Network Activity
    description: Detects suspicious network connections initiated by uncommon processes, potentially indicating command and control activity.
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

CrowdStrike has introduced Charlotte AI AgentWorks and Charlotte Agentic SOAR as part of its Falcon platform, designed to revolutionize security operations by leveraging AI-driven autonomous agents. Launched in March 2026, AgentWorks acts as a central hub for building, scaling, and integrating security agents across the enterprise. It incorporates leading AI models from Anthropic, NVIDIA, and OpenAI, along with AI infrastructure services like Amazon Bedrock and Amazon SageMaker. Agentic SOAR serves as the orchestration layer, enabling customers to activate and coordinate these agents within complex workflows, while maintaining necessary human oversight and security guardrails. The primary objective is to enhance analyst capabilities by automating routine tasks such as triage, malware analysis, and exposure prioritization. This initiative aims to reduce manual workloads by 70%, restore team capacity, and improve decision accuracy to over 98%.

## Attack Chain

This document describes the capabilities of a security platform, not an attack chain. The following steps describe a hypothetical attack that could be detected using the platform's capabilities:

1.  Initial Access: An attacker gains initial access through a vulnerability, potentially exploiting a zero-day.
2.  Execution: The attacker executes a malicious payload via a script interpreter like PowerShell.
3.  Persistence: The attacker establishes persistence by creating a scheduled task.
4.  Discovery: The attacker uses built-in tools to enumerate the environment, such as `net.exe` to discover network shares.
5.  Lateral Movement: The attacker utilizes valid credentials or Pass-the-Hash to move laterally to other systems.
6.  Command and Control: The attacker establishes command and control using a custom protocol.
7.  Exfiltration: The attacker exfiltrates sensitive data to an external server.
8.  Impact: The attacker deploys ransomware across the environment, encrypting critical systems.

## Impact

The successful deployment of Charlotte AI AgentWorks and Agentic SOAR aims to mitigate the impact of attacks like the one described above by automating detection and response. If these tools are not in place, organizations face increased manual workloads, slower response times, and potentially greater damage from successful attacks, including data breaches, ransomware deployment, and financial losses. Early adopters have reported a 70% reduction in manual investigation workloads, restoring more than 40 hours of team capacity per week, and achieving greater than 98% decision accuracy. Failure to adopt such AI-driven security measures leaves organizations vulnerable to adversaries who are increasingly leveraging AI in their attacks.

## Recommendation

*   Evaluate and deploy Charlotte AI AgentWorks and Agentic SOAR on the CrowdStrike Falcon platform to leverage AI-driven security automation (Ref: Overview).
*   Utilize the 50 free AI credits offered by CrowdStrike to experiment with and experience agentic operations within your environment (Ref: Activate Charlotte AI with Free Credits Today).
*   Deploy mission-ready agents across the Falcon platform modules to offload high-friction tasks, such as malware analysis and exposure prioritization (Ref: Charlotte Agentic SOAR).
*   Implement the provided Sigma rules to detect suspicious PowerShell command lines (Ref: rules).
