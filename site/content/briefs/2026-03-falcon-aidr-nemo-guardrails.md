---
title: CrowdStrike Falcon AIDR and NVIDIA NeMo Guardrails Secure AI Agents
slug: 2026-03-falcon-aidr-nemo-guardrails
description: CrowdStrike Falcon AIDR now supports NVIDIA NeMo Guardrails (v0.20.0), providing enterprise-grade protection for AI agents by managing data access, controlling responses, ensuring policy compliance, and blocking prompt injection attacks.
date: "2026-03-28T08:28:28Z"
severities:
  - high
tags:
  - AI-security
  - prompt-injection
  - data-protection
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1566
    technique_name: Phishing
references:
  - https://crowdstrike.com/en-us/blog/secure-homegrown-ai-agents-with-crowdstrike-falcon-aidr-and-nvidia-nemo-guardrails/
rules:
  - title: Detect Suspicious AI Agent Command Line Activity
    description: Detects suspicious command-line activity potentially indicative of prompt injection or malicious manipulation of AI agents.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1566
    data_sources:
      - process_creation
      - windows
  - title: Detect AI Agent Accessing Sensitive Files
    description: Detects AI agents accessing files containing sensitive data, potentially indicative of data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - file_event
      - windows
rules_count: 2
---

The integration of CrowdStrike Falcon AIDR with NVIDIA NeMo Guardrails (v0.20.0) addresses the critical need to secure AI agents transitioning from experimental projects to mainstream business tools. A compromised AI agent can expose customer data, execute unauthorized transactions, and violate compliance requirements across numerous interactions. This new capability aims to limit the scope of AI agents to stay within stated business goals and prevent abuse. CrowdStrike Falcon AIDR and NVIDIA…
