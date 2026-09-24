---
title: Decepticon Agent Framework Role-Boundary Forgery via ChatML Special-Token Literals
slug: 2026-09-decepticon-role-boundary-forgery
description: The Decepticon agent framework fails to sanitize model-specific special-token literals in external reconnaissance data, allowing attackers to forge system-level instructions and execute arbitrary commands in the agent's Kali Linux sandbox.
date: "2026-09-24T20:04:18Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - agent-security
  - llm-security
  - prompt-injection
  - rce
vendors:
  - PurpleAILAB
products:
  - Decepticon (<= 1.1.16)
  - decepticon-core (<= 1.1.16)
  - decepticon-sdk (<= 1.1.16)
affected_os:
  - Kali Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: This forces the LLM to process content as a new authoritative system turn, bypassing agent guardrails and enabling arbitrary command execution within the Kali Linux sandbox environment.
    confidence_band: high
cves:
  - id: CVE-2026-61732
    cvss: 10
references:
  - https://github.com/advisories/GHSA-g5f9-3xfg-p9mf
  - https://github.com/openclaw/openclaw/commit/2514746b3261
action_plan:
  priority: immediate_escalation
  owners:
    - Detection Engineering
    - AppSec
  immediate_actions:
    - action: Upgrade Decepticon components to versions > 1.1.16
      owner: IT Operations
      due: 24h
      evidence: Source states versions <= 1.1.16 are vulnerable
  mitigation_plan:
    - priority: immediate
      action: Deploy application-layer sanitization for ChatML and model-specific special tokens
      owner: Development
      addresses: CVE-2026-61732
      evidence: Remediation section requires filtering tokens before composition
---

Decepticon (v1.1.16 and earlier) is vulnerable to a role-boundary forgery attack caused by the inclusion of unsanitized ChatML and other model-specific special-token literals in LLM message pipelines. The framework aggregates reconnaissance data from external tools - such as web crawlers, Nmap, and HTTP probes - into LLM context windows without neutralizing structural tokens. 

When Decepticon is deployed using a BYOK model with OpenAI-compatible backends (e.g., vLLM, SGLang) that do not strip special-token literals server-side, an attacker can embed malicious literals like `<|im_start|>system` in a target web page. The model interprets these literals as structural boundaries, causing it to incorrectly transition from the "tool" role to a forged "system" turn. This bypasses agentic guardrails and allows the attacker to force the model to execute arbitrary shell commands within the underlying Kali Linux sandbox container used for exploit execution.

## Attack Chain

1. Attacker hosts a malicious web page containing hidden ChatML literals (e.g., `<|im_start|>system`) and a command payload.
2. The Decepticon recon agent initiates a scan using a tool like `katana` against the attacker-controlled target.
3. The agent receives the HTTP response containing the malicious ChatML literals and stores the output as raw string data.
4. The Decepticon `llm/factory.py` logic composes an LLM message list, wrapping the raw tool output without performing sanitization.
5. The framework transmits the unsanitized messages to the LLM backend via the `ChatOpenAI` subclass `ainvoke()` method.
6. The backend tokenizer translates the embedded ChatML literals into structural role-boundary IDs, causing the model to treat the attacker payload as an authoritative system instruction.
7. The agent's model logic follows the forged instruction to call `backends/http_sandbox.py` with an arbitrary command.
8. The Kali Linux sandbox executes the injected shell command, resulting in complete container compromise.

## Impact

Successful exploitation allows for arbitrary code execution (ACE) within the isolated Kali Linux sandbox container. While the sandbox provides a level of isolation, the agent's architecture gives it access to reconnaissance data and potentially other internal network resources reachable from the container environment. The vulnerability impacts all 16 specialist agents within the Decepticon framework and is confirmed against common model providers like vLLM and SGLang.

## Recommendation

1. Patch immediately by upgrading `decepticon`, `decepticon-core`, and `decepticon-sdk` to a version that implements literal filtering.
2. Implement an application-layer sanitization step in the LLM message composition pipeline that strips or escapes known special-token literals (e.g., `<|im_start|`, `<|im_end|`, `<|begin_of_text|>`) before ingestion into the context window.
3. Reference the remediation logic provided in OpenClaw commit `2514746b3261` as a verified mitigation pattern.
4. Perform regression testing on the tokenizer's chat template output to ensure special-token literals are correctly neutralized by the application logic before reaching the LLM inference layer.
