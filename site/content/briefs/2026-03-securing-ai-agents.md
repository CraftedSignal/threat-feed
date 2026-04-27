---
title: CrowdStrike Falcon Enhancements Secure AI Agents and Govern Shadow AI
slug: 2026-03-securing-ai-agents
description: CrowdStrike is enhancing its Falcon platform with AI Detection and Response (AIDR) to secure AI agents and govern shadow AI across endpoints, SaaS, and cloud, addressing threats like prompt injection attacks, data leaks, and policy violations.
date: "2026-03-28T09:23:42Z"
severities:
  - high
tags:
  - ai
  - shadow-ai
  - prompt-injection
  - data-leak
  - endpoint-security
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1199
    technique_name: Bypass User Account Control
references:
  - https://crowdstrike.com/en-us/blog/new-crowdstrike-innovations-secure-ai-agents-govern-shadow-ai/
rules:
  - title: Detect Suspicious AI Agent Processes
    description: Detects processes associated with AI agents that may be indicative of malicious activity or unauthorized use.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - windows
  - title: Detect Prompt Injection Attempts via Command Line
    description: Detects command-line arguments indicative of prompt injection attacks against AI agents.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1199
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike is addressing the emerging attack surface presented by the rapid adoption of AI tools, AI agents, and AI-powered software. Traditional security controls are insufficient to protect against novel threats like indirect prompt injection and agentic tool chain attacks, exacerbated by shadow AI. The CrowdStrike Falcon platform is being enhanced with AI Detection and Response (AIDR) capabilities to secure AI workforce adoption and development across endpoints, SaaS environments, and cloud…
