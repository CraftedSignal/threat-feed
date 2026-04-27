---
title: CrowdStrike Falcon AIDR and NVIDIA NeMo Guardrails Secure AI Agents
slug: 2026-03-falcon-aidr-nemo
description: CrowdStrike Falcon AIDR now supports NVIDIA NeMo Guardrails (v0.20.0) to protect AI agents in production by blocking prompt injection, redacting sensitive data, defanging malicious content, and moderating unwanted topics.
date: "2026-03-19T06:58:32Z"
severities:
  - high
tags:
  - AI-security
  - prompt-injection
  - data-protection
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://crowdstrike.com/en-us/blog/secure-homegrown-ai-agents-with-crowdstrike-falcon-aidr-and-nvidia-nemo-guardrails/
rules:
  - title: Detect Potential Prompt Injection Attempts via HTTP Request
    description: Detects HTTP requests that might be indicative of prompt injection attacks against AI agents by searching for common injection keywords in the query parameters.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1059.003
    data_sources:
      - webserver
      - linux
  - title: Detect Potential Prompt Injection Attempts via HTTP Request - Jailbreak Keywords
    description: Detects HTTP requests that might be indicative of prompt injection attacks against AI agents by searching for jailbreak keywords in the query parameters.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1059.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

As AI agents transition from experimental projects to mainstream business tools, the need to limit their scope and prevent abuse becomes critical. A compromised agent can expose customer data, execute unauthorized transactions, or violate compliance requirements across thousands of interactions. CrowdStrike Falcon AIDR now supports NVIDIA NeMo Guardrails (v0.20.0), delivering enterprise-grade protection for AI agents. NVIDIA NeMo Guardrails is an open-source library for adding programmable…
