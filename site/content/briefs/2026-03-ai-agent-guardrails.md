---
title: Securing AI Agents with CrowdStrike Falcon AIDR and NVIDIA NeMo Guardrails
slug: 2026-03-ai-agent-guardrails
description: CrowdStrike Falcon AIDR now supports NVIDIA NeMo Guardrails to protect AI agents from attacks like prompt injection, data exfiltration, and unauthorized actions, enabling organizations to deploy AI applications more securely.
date: "2026-03-28T21:52:45Z"
severities:
  - high
tags:
  - ai-security
  - prompt-injection
  - data-protection
  - ai-agents
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://www.crowdstrike.com/en-us/blog/secure-homegrown-ai-agents-with-crowdstrike-falcon-aidr-and-nvidia-nemo-guardrails/
rules:
  - title: Detect Suspicious Prompt Injection Attempts
    description: Detects suspicious prompts containing characters or patterns indicative of prompt injection attacks targeting AI agents.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Sensitive Data Exposure by AI Agents
    description: Detects AI agent responses containing sensitive data patterns, indicating potential data leakage.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The increasing adoption of AI agents in enterprise environments presents new security challenges. Attackers are developing techniques to compromise these agents, leading to data breaches, unauthorized transactions, and compliance violations. CrowdStrike Falcon AIDR, with the integration of NVIDIA NeMo Guardrails (version 0.20.0), offers enterprise-grade protection for AI agents. This integration allows organizations to define and enforce guardrails, manage data access, control agent responses…
