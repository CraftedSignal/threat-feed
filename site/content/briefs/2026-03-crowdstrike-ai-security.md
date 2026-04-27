---
title: CrowdStrike Falcon Enhancements for Securing AI Agents and Shadow AI
slug: 2026-03-crowdstrike-ai-security
description: CrowdStrike is enhancing its Falcon platform with new AI Detection and Response (AIDR) capabilities to secure AI agent adoption and development across endpoints, SaaS, and cloud environments, addressing threats like prompt injection, data leaks, and policy violations.
date: "2026-03-23T07:11:28Z"
severities:
  - medium
tags:
  - AI-security
  - shadow-AI
  - endpoint-security
  - saas-security
  - cloud-security
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://www.crowdstrike.com/en-us/blog/new-crowdstrike-innovations-secure-ai-agents-govern-shadow-ai/
rules:
  - title: Detect Suspicious AI Application Usage
    description: Detects the execution of AI-related applications on endpoints, potentially indicating unauthorized usage or shadow AI.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - process_creation
      - windows
  - title: Detect Network Connection from AI Related Processes
    description: Detects network connections from AI related processes which may indicate data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CrowdStrike is introducing new capabilities within its Falcon platform to address the emerging security challenges presented by the increasing adoption of AI tools and agents within organizations. The focus is on mitigating risks associated with "shadow AI" (AI tools used without proper oversight) and securing AI agents against novel threats like indirect prompt injection and agentic tool chain attacks. These enhancements aim to provide visibility, governance, and runtime protection for AI…
