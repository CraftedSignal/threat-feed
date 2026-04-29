---
title: CrowdStrike Falcon AIDR and NVIDIA NeMo Guardrails Secure AI Agents
slug: 2026-03-falcon-aidr-nemo
description: CrowdStrike Falcon AIDR now supports NVIDIA NeMo Guardrails (v0.20.0) to protect AI agents in production by blocking prompt injection, redacting sensitive data, defanging malicious content, and moderating unwanted topics.
date: "2026-03-19T06:58:32Z"
type: coverage
types:
  - coverage
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

As AI agents transition from experimental projects to mainstream business tools, the need to limit their scope and prevent abuse becomes critical. A compromised agent can expose customer data, execute unauthorized transactions, or violate compliance requirements across thousands of interactions. CrowdStrike Falcon AIDR now supports NVIDIA NeMo Guardrails (v0.20.0), delivering enterprise-grade protection for AI agents. NVIDIA NeMo Guardrails is an open-source library for adding programmable guardrails to LLMs and agentic applications, including Nemotron Safety models for content safety, PII, jailbreak detection, and topic control. Falcon AIDR with NVIDIA NeMo Guardrails enables organizations to manage agentic data access, control agent responses, and manage access to tools and data sources.

## Attack Chain

1.  Initial Access: An attacker gains access to an AI agent through various means, such as exploiting a vulnerability in the agent's code or infrastructure, or through social engineering.
2.  Prompt Injection: The attacker crafts a malicious prompt designed to manipulate the agent's behavior and bypass intended guardrails. This could involve injecting commands or instructions into the agent's input.
3.  Bypass Guardrails: The injected prompt successfully bypasses the AI agent's initial security checks and guardrails, allowing the attacker to influence its actions.
4.  Data Exfiltration: The attacker leverages the compromised agent to access and exfiltrate sensitive data, such as customer PII, financial records, or proprietary information.
5.  Unauthorized Actions: The attacker manipulates the agent to perform unauthorized actions, such as executing transactions, modifying configurations, or accessing restricted resources.
6.  Lateral Movement: The attacker uses the compromised agent as a foothold to move laterally within the organization's network, targeting other systems and applications.
7.  Privilege Escalation: The attacker attempts to escalate their privileges within the compromised system or network, gaining access to more sensitive resources and capabilities.

## Impact

A successful attack can lead to the exposure of sensitive customer data, unauthorized transactions, and violations of compliance requirements across thousands of interactions. This can result in significant financial losses, reputational damage, legal liabilities, and regulatory penalties. Organizations in financial services, healthcare, customer service, and software development are particularly vulnerable.

## Recommendation

*   Implement CrowdStrike Falcon AIDR with NVIDIA NeMo Guardrails (v0.20.0) to protect AI agents against runtime attacks and reduce the blast radius of compromises.
*   Utilize NVIDIA NeMo Guardrails' Nemotron Safety models to enforce content safety, PII protection, jailbreak detection, and topic control.
*   Enable Falcon AIDR policies to block prompt injection attacks, redact sensitive data, defang malicious content, and moderate unwanted topics.
*   Configure Falcon AIDR policies tailored to specific security requirements, defining detectors and action modes for scenarios like chat input sanitization and RAG data ingestion.
*   Monitor Falcon AIDR logs and alerts to identify and respond to potential attacks against AI agents.
