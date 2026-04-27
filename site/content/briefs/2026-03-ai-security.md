---
title: CrowdStrike Falcon Enhancements for Securing AI Agents and Governing Shadow AI
slug: 2026-03-ai-security
description: CrowdStrike is enhancing its Falcon platform with new AI detection and response capabilities to secure AI agents and govern shadow AI across endpoints, SaaS, and cloud environments, addressing threats like prompt injection and data leaks.
date: "2026-03-28T08:12:22Z"
severities:
  - medium
tags:
  - AI-Security
  - Shadow-AI
  - Endpoint-Security
references:
  - https://crowdstrike.com/en-us/blog/new-crowdstrike-innovations-secure-ai-agents-govern-shadow-ai/
rules:
  - title: Detect AI Application Usage
    description: Detects the execution of common AI desktop applications such as ChatGPT, Gemini, and Microsoft Copilot, providing visibility into shadow AI usage.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1518
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Network Connection from AI Applications
    description: Detects potentially malicious outbound network connections initiated from AI-related applications.
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

CrowdStrike is addressing the emerging security challenges posed by the rapid adoption of AI tools and agents within organizations. The increasing use of AI, particularly on endpoints and within SaaS environments, creates new attack surfaces that traditional security measures are ill-equipped to handle. These surfaces include vulnerabilities related to prompt injection, agentic tool chain attacks, and data leaks. The rise of shadow AI, where employees adopt AI tools without proper oversight…
