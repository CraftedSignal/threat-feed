---
title: CrowdStrike Innovations Secure AI Agents and Govern Shadow AI
slug: 2026-03-shadow-ai-governance
description: CrowdStrike is introducing innovations to secure AI agents and govern shadow AI across endpoints, SaaS, and cloud environments by extending AI detection and response (AIDR) capabilities to cover desktop AI applications and provide visibility into AI-related components, helping to prevent prompt attacks, data leaks, and policy violations.
date: "2026-03-28T21:52:45Z"
severities:
  - medium
tags:
  - AI
  - AI-Security
  - Shadow-AI
  - Endpoint-Security
  - SaaS
  - Cloud
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
references:
  - https://www.crowdstrike.com/en-us/blog/new-crowdstrike-innovations-secure-ai-agents-govern-shadow-ai/
rules:
  - title: AI Desktop Application Usage Detected
    description: Detects the execution of common AI desktop applications.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - process_creation
      - windows
  - title: Potential AI Related Process Discovery
    description: Detects processes that are potentially related to AI models
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

CrowdStrike is addressing the emerging threat landscape created by the rapid adoption of AI tools and agents within organizations. The increasing use of personal AI agents, particularly on developer machines, introduces new attack vectors such as "living off the AI land" (LOTAIL) exploits, indirect prompt injection, and agentic tool chain attacks. The rise of shadow AI, where employees adopt AI tools without oversight, exacerbates the issue. CrowdStrike's new innovations extend AI Detection and…
