---
title: CrowdStrike Falcon Enhancements for Securing AI Environments
slug: 2026-03-crowdstrike-ai-security
description: CrowdStrike is enhancing its Falcon platform with new features focusing on AI Detection and Response (AIDR) capabilities across endpoints, SaaS, and cloud environments to mitigate risks such as prompt injection attacks, data leaks, and policy violations related to AI agents and shadow AI.
date: "2026-03-28T09:35:50Z"
severities:
  - medium
tags:
  - ai
  - security
  - falcon
  - agentic-soc
  - prompt-injection
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1202
    technique_name: Exploitation for Defense Evasion
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
references:
  - https://crowdstrike.com/en-us/blog/new-crowdstrike-innovations-secure-ai-agents-govern-shadow-ai/
rules:
  - title: Detect Suspicious Execution from AI Desktop Applications
    description: Detects suspicious execution of commands or scripts initiated from known AI desktop applications such as ChatGPT, Gemini, or Microsoft Copilot, which could indicate prompt injection or other malicious activity.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect AI related processes
    description: Detects execution of AI related processes such as MCP Servers
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike is addressing the emerging threats associated with the rapid adoption of AI tools and AI-powered software by enhancing its Falcon platform. These enhancements focus on providing AI Detection and Response (AIDR) capabilities across endpoints, SaaS environments, and cloud environments. The core issue being addressed is the increasing attack surface created by novel threats, such as indirect prompt injection and agentic tool chain attacks, alongside the widespread adoption of shadow…
