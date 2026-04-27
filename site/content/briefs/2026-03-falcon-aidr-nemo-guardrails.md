---
title: CrowdStrike Falcon AIDR with NVIDIA NeMo Guardrails Secures AI Agents
slug: 2026-03-falcon-aidr-nemo-guardrails
description: CrowdStrike Falcon AIDR now supports NVIDIA NeMo Guardrails (v0.20.0), providing enterprise-grade protection against attacks targeting AI agents by blocking prompt injection, redacting sensitive data, defanging malicious content, and moderating unwanted topics to ensure policy compliance and data safety.
date: "2026-03-28T08:15:24Z"
severities:
  - high
tags:
  - ai-security
  - prompt-injection
  - data-protection
  - llm
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
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://crowdstrike.com/en-us/blog/secure-homegrown-ai-agents-with-crowdstrike-falcon-aidr-and-nvidia-nemo-guardrails/
rules:
  - title: Detect Prompt Injection Attempts via HTTP Request
    description: Detects potential prompt injection attacks based on keywords in HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect AI Agent Access to Sensitive Data Files
    description: Detects AI agents accessing files containing sensitive information (PII, PHI).
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - discovery
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CrowdStrike Falcon AIDR has integrated NVIDIA NeMo Guardrails (v0.20.0) to provide enhanced security for AI agents. As AI agents transition from experimental projects to mainstream business tools, the risk of compromise increases significantly, potentially exposing sensitive customer data, enabling unauthorized transactions, and violating compliance requirements. This integration addresses the challenge of limiting AI agent scope and preventing abuse, offering organizations a framework to apply…
