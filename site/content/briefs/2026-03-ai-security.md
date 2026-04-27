---
title: CrowdStrike Falcon Enhancements for AI Agent Security and Shadow AI Governance
slug: 2026-03-ai-security
description: CrowdStrike is enhancing its Falcon platform to secure AI agents and govern shadow AI across endpoints, SaaS, and cloud environments, providing new detection and response capabilities for desktop AI applications, AI component discovery, and runtime security for Copilot Studio agents.
date: "2026-03-23T00:00:00Z"
severities:
  - medium
tags:
  - ai-security
  - shadow-ai
  - agentic-soc
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://crowdstrike.com/en-us/blog/new-crowdstrike-innovations-secure-ai-agents-govern-shadow-ai/
rules:
  - title: Detect AI Application Execution on Endpoint
    description: Detects the execution of known AI applications on endpoints, providing visibility into their usage.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - process_creation
      - windows
  - title: Detect AI Related Network Connection
    description: Detects the network connection related to AI application by filtering with process and destiantion address
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

CrowdStrike is addressing the emerging attack surface created by the rapid adoption of AI tools and AI agents within organizations. The Falcon platform is being enhanced to provide visibility, governance, and runtime protection for AI across endpoints, SaaS, and cloud environments. This includes addressing novel threats such as indirect prompt injection and agentic tool chain attacks. The rise of shadow AI, where employees and engineering teams deploy AI tools without adequate oversight, is…
