---
title: Securing AI Agents with Falcon AIDR and NVIDIA NeMo Guardrails
slug: 2026-03-falcon-aidr-nemo
description: CrowdStrike Falcon AIDR now supports NVIDIA NeMo Guardrails to protect AI agents by blocking prompt injection attacks, redacting sensitive data, defanging malicious content, and moderating unwanted topics, ensuring compliance and preventing abuse.
date: "2026-03-29T06:23:07Z"
severities:
  - medium
tags:
  - ai-security
  - prompt-injection
  - data-protection
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
references:
  - https://crowdstrike.com/en-us/blog/secure-homegrown-ai-agents-with-crowdstrike-falcon-aidr-and-nvidia-nemo-guardrails/
rules:
  - title: Detect Prompt Injection Attempts
    description: Detects potential prompt injection attempts by identifying specific keywords and patterns in user inputs to AI agents.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Data Redaction Failures in AI Agent Logs
    description: Detects potential failures in data redaction by monitoring for patterns resembling sensitive data (e.g., SSNs, account numbers) in AI agent logs after redaction processes.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    data_sources:
      - webserver
      - linux
  - title: Detect AI Agent Access to Blocked Domains
    description: Detects when an AI agent attempts to access a domain that should be blocked by Falcon AIDR's content defanging capabilities.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

The increasing adoption of AI agents in business-critical processes introduces new security challenges. As these agents transition from experimental projects to mainstream tools, the risk of compromise rises, potentially exposing customer data, executing unauthorized transactions, or violating compliance requirements. CrowdStrike Falcon AIDR, with the integration of NVIDIA NeMo Guardrails (version 0.20.0), provides enterprise-grade protection for AI agents. This combination enables…
