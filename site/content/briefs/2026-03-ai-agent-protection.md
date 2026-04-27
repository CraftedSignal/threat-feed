---
title: CrowdStrike Falcon AIDR Supports NVIDIA NeMo Guardrails for AI Agent Protection
slug: 2026-03-ai-agent-protection
description: CrowdStrike Falcon AIDR now supports NVIDIA NeMo Guardrails, providing enterprise-grade protection for AI agents by defending against runtime attacks like prompt injection, redacting sensitive data, defanging malicious content, and moderating unwanted topics to ensure agents stay within compliance boundaries in sectors like finance, healthcare, customer service, and software development.
date: "2026-03-28T22:14:01Z"
severities:
  - high
tags:
  - ai-security
  - prompt-injection
  - data-exfiltration
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1566
    technique_name: Phishing
references:
  - https://crowdstrike.com/en-us/blog/secure-homegrown-ai-agents-with-crowdstrike-falcon-aidr-and-nvidia-nemo-guardrails/
rules:
  - title: Detect AI Agent Prompt Injection Attempts via User Input
    description: Detects potential prompt injection attacks by monitoring user inputs for suspicious patterns commonly used to manipulate AI agents.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - webserver
      - linux
  - title: Detect AI Agent Data Exfiltration via Abnormal Network Activity
    description: Detects potential data exfiltration attempts by AI agents by monitoring network connections for unusual patterns.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The increasing adoption of AI agents in mainstream business operations has created a critical need for robust security measures. CrowdStrike Falcon AIDR now supports NVIDIA NeMo Guardrails (v0.20.0), offering enterprise-grade protection for these AI agents. This integration addresses the challenge of limiting the scope of AI agent actions to prevent abuse and ensure compliance with business goals. It provides a framework that applies constraints on the capabilities of large language models…
