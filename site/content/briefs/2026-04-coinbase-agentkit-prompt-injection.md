---
title: Coinbase AgentKit Prompt Injection Vulnerability
slug: 2026-04-coinbase-agentkit-prompt-injection
description: A prompt injection vulnerability in Coinbase AgentKit allows for potential wallet drain, infinite approvals, and agent-level remote code execution.
date: "2026-04-14T00:00:00Z"
severities:
  - critical
tags:
  - prompt-injection
  - coinbase
  - agentkit
  - wallet-drain
references:
  - https://www.reddit.com/r/netsec/comments/1skfumg/coinbase_agentkit_prompt_injection_wallet_drain/
  - https://x402warden.com/research/coinbase-agentkit-prompt-injection/
ioc_counts:
  url: 2
rules:
  - title: Detect Suspicious AgentKit Prompt Injection
    description: Detects potential prompt injection attempts targeting Coinbase AgentKit based on suspicious keywords in URI queries.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious AgentKit HTTP Method Usage
    description: Detects potential abuse of AgentKit endpoints through unexpected HTTP methods.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability has been identified in Coinbase's AgentKit, a framework used for creating AI agents. This vulnerability stems from a prompt injection flaw that could be exploited to achieve several malicious outcomes, including draining user wallets, granting infinite transaction approvals, and even achieving remote code execution at the agent level. The vulnerability, validated by Coinbase with on-chain proof-of-concept, highlights the risks associated with integrating AI agents into…
