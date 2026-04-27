---
title: CrowdStrike Falcon Enhancements for AI Agent Security
slug: 2026-03-ai-agent-security
description: CrowdStrike is enhancing its Falcon platform with new AI detection and response (AIDR) capabilities to secure AI agents and govern shadow AI across endpoints, SaaS, and cloud environments, addressing threats like indirect prompt injection, agentic tool chain attacks, and risks associated with shadow AI adoption.
date: "2026-03-23T00:00:00Z"
severities:
  - high
tags:
  - ai
  - agentic-soc
  - shadow-ai
  - endpoint-security
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://crowdstrike.com/en-us/blog/new-crowdstrike-innovations-secure-ai-agents-govern-shadow-ai/
rules:
  - title: Detect Suspicious AI Application Network Connection
    description: Detects network connections initiated by known AI applications that may indicate malicious activity or data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect AI Application Process Creation
    description: Detects process creation events for known AI applications.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike is introducing new innovations to its Falcon platform to address the emerging security challenges associated with the rapid adoption of AI tools and agents across endpoints, SaaS, and cloud environments. The updates aim to close the AI visibility and governance gap resulting from shadow AI adoption and the deployment of AI agents without adequate security controls.  These enhancements include AI Detection and Response (AIDR) capabilities for desktop AI applications and deep agent…
