---
title: Coinbase AgentKit Prompt Injection Vulnerability
slug: 2026-04-coinbase-agentkit-prompt-injection
description: A prompt injection vulnerability in Coinbase AgentKit allows for potential wallet drain, infinite approvals, and agent-level remote code execution.
date: "2026-04-14T00:00:00Z"
type: advisory
types:
  - advisory
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
iocs:
  - type: url
    value: https://x402warden.com/research/coinbase-agentkit-prompt-injection/
  - type: url
    value: https://www.reddit.com/r/netsec/comments/1skfumg/coinbase_agentkit_prompt_injection_wallet_drain/
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

A critical vulnerability has been identified in Coinbase's AgentKit, a framework used for creating AI agents. This vulnerability stems from a prompt injection flaw that could be exploited to achieve several malicious outcomes, including draining user wallets, granting infinite transaction approvals, and even achieving remote code execution at the agent level. The vulnerability, validated by Coinbase with on-chain proof-of-concept, highlights the risks associated with integrating AI agents into sensitive financial platforms. Defenders need to understand the potential attack vectors and implement mitigations to prevent exploitation of this flaw, especially as AI-powered financial tools become more prevalent. The impact of successful exploitation could range from individual user losses to widespread platform compromise, making it a high-priority threat.

## Attack Chain

1. An attacker crafts a malicious prompt containing instructions designed to manipulate the AgentKit.
2. The malicious prompt is injected into the AgentKit via user input or data feed.
3. The AgentKit processes the injected prompt, misinterpreting the attacker's instructions as legitimate commands.
4. The manipulated AgentKit interacts with the user's Coinbase wallet.
5. The attacker leverages the prompt injection to initiate unauthorized transactions, draining the wallet.
6. Alternatively, the attacker could manipulate the AgentKit to grant infinite approval permissions for specific contracts.
7. If successful, the attacker achieves agent-level remote code execution, allowing full control over the AgentKit instance.
8. The attacker can then propagate the attack to other users or systems connected to the compromised AgentKit.

## Impact

Successful exploitation of the AgentKit prompt injection vulnerability could lead to significant financial losses for Coinbase users. Attackers could drain wallets, steal cryptocurrency assets, and gain unauthorized access to user accounts. The potential for infinite approval grants further exacerbates the risk, enabling attackers to repeatedly withdraw funds over an extended period. Furthermore, agent-level RCE allows for complete compromise of AgentKit instances, potentially affecting a large number of users and impacting the overall security and trust of the Coinbase platform. The number of potential victims is substantial given Coinbase's user base.

## Recommendation

*   Inspect web server logs for suspicious URLs related to the AgentKit endpoints to identify potential exploitation attempts (webserver, linux).
*   Implement input validation and sanitization measures to prevent prompt injection attacks within AgentKit, focusing on areas where user-supplied prompts are processed (application code review).
*   Deploy the Sigma rule to detect exploitation attempts by identifying suspicious keywords in HTTP request URIs (rule: "Detect Suspicious AgentKit Prompt Injection").
*   Monitor network traffic for connections to potentially malicious URLs associated with known prompt injection attacks (IOC: https://x402warden.com/research/coinbase-agentkit-prompt-injection/).
