---
title: CrowdStrike Charlotte AI AgentWorks and Agentic SOAR for Enhanced Security Operations
slug: 2026-03-charlotte-ai-agentworks
description: CrowdStrike's Charlotte AI AgentWorks and Agentic SOAR aim to improve security operations by enabling AI-powered autonomous agents, orchestrated to amplify analyst capabilities and automate tasks like malware analysis and exposure prioritization, reducing manual workloads and increasing decision accuracy.
date: "2026-03-28T08:17:38Z"
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

CrowdStrike has introduced Charlotte AI AgentWorks and Charlotte Agentic SOAR as part of its Falcon platform, designed to revolutionize security operations by leveraging AI-driven autonomous agents. Launched in March 2026, AgentWorks acts as a central hub for building, scaling, and integrating security agents across the enterprise. It incorporates leading AI models from Anthropic, NVIDIA, and OpenAI, along with AI infrastructure services like Amazon Bedrock and Amazon SageMaker. Agentic SOAR…
