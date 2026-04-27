---
title: CrowdStrike Falcon Enhancements for AI Agent Security and Shadow AI Governance
slug: 2026-03-ai-agent-security
description: CrowdStrike Falcon is enhanced to secure AI agents and govern shadow AI across endpoints, SaaS, and cloud environments, addressing emerging attack surfaces and visibility gaps.
date: "2026-03-28T08:18:48Z"
severities:
  - medium
tags:
  - ai-security
  - shadow-ai
  - agentic-soc
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1518
    technique_name: Software Discovery
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://crowdstrike.com/en-us/blog/new-crowdstrike-innovations-secure-ai-agents-govern-shadow-ai/
rules:
  - title: Detect AI Agent Installation
    description: Detects the installation of known AI-related applications on endpoints.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1518.001
    data_sources:
      - process_creation
      - windows
  - title: Detect AI Agent Network Activity
    description: Detects network connections initiated by known AI applications, potentially indicating data exfiltration or command and control.
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

CrowdStrike is enhancing its Falcon platform to address the emerging security challenges presented by the rapid adoption of AI tools and the rise of "shadow AI." The Falcon platform's enhancements aim to close AI visibility and governance gaps. The new capabilities include AI Detection and Response (AIDR) for desktop AI applications like ChatGPT, Gemini, Claude, DeepSeek, Microsoft Copilot, O365 Copilot, GitHub Copilot, and Cursor. AIDR is also extending runtime security to agents built in…
