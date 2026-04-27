---
title: CrowdStrike Falcon AIDR Supports NVIDIA NeMo Guardrails for AI Agent Protection
slug: 2026-03-ai-guardrails
description: CrowdStrike Falcon AIDR now supports NVIDIA NeMo Guardrails (v0.20.0) to protect AI agents from prompt injection, data exposure, and unauthorized actions, enabling safer deployment of AI applications.
date: "2026-03-19T06:19:01Z"
severities:
  - high
tags:
  - ai-security
  - prompt-injection
  - data-protection
  - guardrails
  - agentic-ai
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://crowdstrike.com/en-us/blog/secure-homegrown-ai-agents-with-crowdstrike-falcon-aidr-and-nvidia-nemo-guardrails/
rules:
  - title: Detect Potential Prompt Injection Attacks via HTTP Request
    description: Detects HTTP requests indicative of prompt injection attacks targeting AI agents by looking for specific keywords in the request URI.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Unauthorized Tool Invocation by AI Agent
    description: Detects potential unauthorized tool invocations by AI agents by monitoring process creation events with specific command-line arguments related to tool execution.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

As AI agents transition from experimental projects to mainstream business tools, the risk of compromise increases, potentially leading to data exposure, unauthorized transactions, and compliance violations. CrowdStrike Falcon AIDR, with the integration of NVIDIA NeMo Guardrails (v0.20.0), aims to mitigate these risks by providing enterprise-grade protection for AI applications. This integration allows organizations to define guardrails and apply constraints on LLMs, managing data access…
