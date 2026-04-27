---
title: CrowdStrike Falcon Enhancements for Securing AI Agents and Governing Shadow AI
slug: 2026-03-ai-security
description: CrowdStrike is enhancing its Falcon platform to secure AI agents and govern shadow AI across endpoints, SaaS, and cloud environments, including AI Detection and Response (AIDR) capabilities extended to desktop AI applications and AI Discovery in Falcon Exposure Management.
date: "2026-03-25T10:00:00Z"
severities:
  - medium
tags:
  - AI-security
  - shadow-AI
  - endpoint-security
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://crowdstrike.com/en-us/blog/new-crowdstrike-innovations-secure-ai-agents-govern-shadow-ai/
rules:
  - title: Detect AI Application Execution via Command Line
    description: Detects the execution of known AI applications via command line, which could indicate malicious activity or unauthorized usage.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
  - title: Detect AI Discovery MCP Server Connection
    description: Detects network connections to MCP servers, potentially indicating AI component interaction.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1016
    data_sources:
      - network_connection
      - windows
  - title: Detect Falcon AIDR Browser Extension Installation
    description: Detects the installation of the CrowdStrike Falcon AIDR browser extension.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    data_sources:
      - file_event
      - windows
rules_count: 3
---

CrowdStrike is introducing new capabilities within its Falcon platform to address the emerging threats associated with the rapid adoption of AI tools and agents. These enhancements focus on securing AI agents, governing shadow AI, and extending AI Detection and Response (AIDR) capabilities across endpoints, SaaS environments, and cloud environments. The rise of shadow AI, where employees adopt AI tools without oversight, combined with the deployment of models and agents lacking adequate runtime…
