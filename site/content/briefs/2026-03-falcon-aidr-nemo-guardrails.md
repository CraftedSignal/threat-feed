---
title: CrowdStrike Falcon AIDR and NVIDIA NeMo Guardrails Secure AI Agents
slug: 2026-03-falcon-aidr-nemo-guardrails
description: CrowdStrike Falcon AIDR now supports NVIDIA NeMo Guardrails as of release v0.20.0, delivering enterprise-grade protection that helps organizations confidently move agentic AI applications from development to production by blocking prompt injection attacks, redacting sensitive data, defanging malicious content, and moderating unwanted topics.
date: "2026-03-30T09:12:24Z"
severities:
  - high
tags:
  - AI
  - Security
  - LLM
  - Prompt Injection
  - Data Protection
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
references:
  - https://crowdstrike.com/en-us/blog/secure-homegrown-ai-agents-with-crowdstrike-falcon-aidr-and-nvidia-nemo-guardrails/
rules:
  - title: Detect Suspicious AI Agent Prompt Injection Attempts
    description: Detects attempts to inject malicious prompts into AI agent interactions by identifying keywords and patterns associated with prompt injection techniques.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect AI Agent Access to Sensitive Data Stores
    description: Detects AI Agents accessing sensitive data stores
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The increasing adoption of AI agents in mainstream business tools introduces new security challenges. As AI agents transition from experimental projects to critical business functions, the potential impact of a compromised agent grows significantly. A single compromised agent can expose customer data, execute unauthorized transactions, or violate compliance requirements across numerous interactions. CrowdStrike Falcon AIDR, in conjunction with NVIDIA NeMo Guardrails (v0.20.0), offers a solution…
