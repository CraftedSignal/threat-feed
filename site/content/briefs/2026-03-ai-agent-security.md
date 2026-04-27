---
title: Securing AI Agents with CrowdStrike Falcon AIDR and NVIDIA NeMo Guardrails
slug: 2026-03-ai-agent-security
description: CrowdStrike Falcon AIDR integrates with NVIDIA NeMo Guardrails to provide comprehensive protection for AI agents against prompt injection, data leaks, and malicious content.
date: "2026-03-28T21:37:25Z"
severities:
  - medium
tags:
  - ai
  - security
  - agentic-soc
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
references:
  - https://crowdstrike.com/en-us/blog/secure-homegrown-ai-agents-with-crowdstrike-falcon-aidr-and-nvidia-nemo-guardrails/
rules:
  - title: Detect Suspicious Keywords in HTTP Requests to AI Agents
    description: Detects potential prompt injection attempts by looking for suspicious keywords in HTTP requests.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - webserver
      - linux
  - title: Detect Blocked Content by Falcon AIDR
    description: Detects instances where Falcon AIDR blocks potentially malicious content based on its classification rules.
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The increasing adoption of AI agents in mainstream business tools presents new security challenges. A compromised agent can lead to data exposure, unauthorized transactions, and compliance violations. To address these risks, CrowdStrike Falcon AIDR now supports NVIDIA NeMo Guardrails. This integration provides enterprise-grade protection by defining guardrails and applying constraints on LLMs. NVIDIA NeMo Guardrails, an open-source library, offers features like content safety, PII detection…
