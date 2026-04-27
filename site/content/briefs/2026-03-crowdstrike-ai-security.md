---
title: CrowdStrike Enhancements to Secure AI Agents and Govern Shadow AI
slug: 2026-03-crowdstrike-ai-security
description: CrowdStrike is releasing new capabilities to extend AI detection and response (AIDR) across endpoints, SaaS, and cloud environments to address the growing attack surface presented by AI agents and shadow AI adoption, including techniques like 'Living Off The AI Land' (LOTAIL).
date: "2026-03-23T09:00:00Z"
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

CrowdStrike is enhancing its Falcon platform to address the emerging threats associated with the increasing adoption of AI agents and shadow AI within organizations. This update focuses on securing AI workforce adoption and development across endpoints, SaaS environments, and cloud infrastructures. With the rise of personal AI agents, a new attack surface is created, leading to techniques like "Living Off The AI Land" (LOTAIL), where adversaries exploit AI agents for malicious purposes. The…
