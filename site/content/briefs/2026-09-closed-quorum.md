---
title: CLOSEDQUORUM Autonomous AI C2 Implant Analysis
slug: 2026-09-closed-quorum
description: CLOSEDQUORUM is a 64-bit Go-based Windows malware implant that uses an autonomous multi-LLM architecture to perform command and control via legitimate commercial API endpoints.
date: "2026-09-22T14:01:30Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
tags:
  - autonomous-malware
  - command-and-control
  - artificial-intelligence
  - windows
  - go
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: CLOSEDQUORUM calls up to four commercial LLM provider endpoints used by thousands of legitimate applications daily.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: CGO_ENABLED=1 confirms the binary mixes Go and C code, which is how it makes direct Windows system calls.
    confidence_band: high
references:
  - https://blog.talosintelligence.com/the-closed-quorum-inside-the-first-reported-autonomous-ai-c2-implant/
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - Detection Engineering
  hunt_leads:
    - lead: Identify persistent HTTPS connections from unusual endpoints to AI model providers (DeepSeek, Qwen, Mistral, Google Gemini).
      technique_id: T1071.001
      data_needed:
        - Network egress logs
        - Proxy logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The CLOSEDQUORUM C2 architecture supports up to four LLM provider integrations.
  mitigation_plan:
    - priority: medium_term
      action: Implement egress filtering policies on endpoints that should not require access to commercial AI API services.
      owner: IT Operations
      addresses: C2 infrastructure
      evidence: CLOSEDQUORUM calls up to four commercial LLM provider endpoints.
---

CLOSEDQUORUM is a 16.4MB, 64-bit Windows executable written in Go that introduces a novel 'LLM-as-C2' architecture, discovered by Cisco Talos during their CAIRN project. Unlike traditional malware that relies on a specific attacker-operated C2 server and protocol, CLOSEDQUORUM delegates its decision-making loop to a panel of up to four commercial Large Language Model (LLM) providers: DeepSeek, Qwen, Mistral, and Google Gemini. 

The implant follows a strict internal process where each model is queried, and the resulting actions are resolved via plurality voting. This architecture aims to bypass traditional network security controls by blending into legitimate traffic patterns directed toward common AI API endpoints. While current public builds contain placeholder API keys and dummy webhooks, the architectural design explicitly targets credential and cryptocurrency wallet harvesting. By offloading decision-making to external AI models, the implant achieves 'effort displacement,' allowing an operation to persist and evolve without continuous human operator interaction.

## Attack Chain

1. The malware executes on the host as a 64-bit Windows binary (Go and C mix, CGO_ENABLED=1).
2. The 'ModelOrchestrator' component initializes API keys for DeepSeek, Qwen, Mistral, and Gemini.
3. The implant triggers a four-provider query loop, invoking 'main.queryLLM' for each provider endpoint.
4. The binary transmits structured prompts to these external APIs, constrained by a system prompt instructing the models to act as 'malware strategists'.
5. The responses are collected and resolved via plurality voting (interModelDiscussion function) to select the next malicious task.
6. The winning decision is executed locally, and the outcome is transmitted via a Discord webhook.
7. If all models fail to return a valid decision, the malware enters a 'consensus' fallback state and triggers a retry loop.

## Impact

While no in-the-wild deployment has been confirmed, the capability of CLOSEDQUORUM demonstrates a shift toward autonomous malware that can perform credential and crypto-wallet harvesting without human-in-the-loop intervention. This increases the complexity of incident response, as detection must pivot from simple domain-based C2 blocking to identifying suspicious patterns of model interaction and API usage.

## Recommendation

Deploy behavioral monitoring to detect persistent, low-frequency HTTPS traffic directed toward commercial AI model API endpoints from non-development/non-research endpoints. Monitor for Discord webhook traffic emanating from suspicious Windows processes. Organizations should scrutinize processes compiled with Go that exhibit CGO-based direct system call patterns for anomalous API interactions.
