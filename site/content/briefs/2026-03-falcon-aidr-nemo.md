---
title: Securing AI Agents with Falcon AIDR and NVIDIA NeMo Guardrails
slug: 2026-03-falcon-aidr-nemo
description: CrowdStrike Falcon AIDR now supports NVIDIA NeMo Guardrails to protect AI agents by blocking prompt injection attacks, redacting sensitive data, defanging malicious content, and moderating unwanted topics, ensuring compliance and preventing abuse.
date: "2026-03-29T06:23:07Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - ai-security
  - prompt-injection
  - data-protection
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
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
references:
  - https://crowdstrike.com/en-us/blog/secure-homegrown-ai-agents-with-crowdstrike-falcon-aidr-and-nvidia-nemo-guardrails/
rules:
  - title: Detect Prompt Injection Attempts
    description: Detects potential prompt injection attempts by identifying specific keywords and patterns in user inputs to AI agents.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Data Redaction Failures in AI Agent Logs
    description: Detects potential failures in data redaction by monitoring for patterns resembling sensitive data (e.g., SSNs, account numbers) in AI agent logs after redaction processes.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    data_sources:
      - webserver
      - linux
  - title: Detect AI Agent Access to Blocked Domains
    description: Detects when an AI agent attempts to access a domain that should be blocked by Falcon AIDR's content defanging capabilities.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

The increasing adoption of AI agents in business-critical processes introduces new security challenges. As these agents transition from experimental projects to mainstream tools, the risk of compromise rises, potentially exposing customer data, executing unauthorized transactions, or violating compliance requirements. CrowdStrike Falcon AIDR, with the integration of NVIDIA NeMo Guardrails (version 0.20.0), provides enterprise-grade protection for AI agents. This combination enables organizations to define guardrails, manage data access, control agent responses, and ensure adherence to custom policies and safety controls, facilitating the secure deployment of AI agents in production environments. The integration focuses on mitigating risks associated with runtime attacks and reducing the impact of potential compromises.

## Attack Chain

1. **Initial Access:** An attacker attempts to interact with an AI agent through a chat interface or API endpoint.
2. **Prompt Injection:** The attacker crafts a malicious prompt designed to manipulate the agent's behavior or extract sensitive information. This leverages the agent's reliance on LLMs to carry out commands.
3. **Bypass Guardrails (Attempted):** The prompt is sent to the AI agent, which then passes it through NVIDIA NeMo Guardrails managed by Falcon AIDR.
4. **Detection and Redaction:** Falcon AIDR detects the prompt injection attempt using its built-in classification rules and custom policies. Sensitive data like PII or internal repository references are redacted.
5. **Content Defanging:** Malicious content, such as adversarial domains embedded in the prompt, is identified and defanged to prevent the agent from accessing or executing compromised workflows.
6. **Policy Enforcement:** The agent's response is moderated to ensure it stays within compliance boundaries, preventing the disclosure of unauthorized information or the execution of unauthorized actions.
7. **Action Blocking:** The agent is blocked from executing any action triggered by the malicious prompt, preventing unauthorized transactions or access to sensitive data.
8. **Safe Response Generation:** The agent generates a safe and compliant response based on the filtered and sanitized input, maintaining a natural conversation flow without compromising security.

## Impact

Compromised AI agents can lead to significant data breaches, unauthorized transactions, and compliance violations, affecting potentially thousands of interactions. The integration of Falcon AIDR and NVIDIA NeMo Guardrails aims to prevent financial losses, reputational damage, and legal repercussions associated with these breaches. The number of affected organizations is expected to rise as AI agents become more integrated into sensitive business processes across various sectors, including financial services, healthcare, customer service, and software development. Success in these attacks could lead to exposure of sensitive patient data, financial records, or intellectual property.

## Recommendation

*   Deploy the provided Sigma rule to detect prompt injection attempts targeting AI agents by monitoring for specific keywords and patterns in user inputs (Sigma rule: "Detect Prompt Injection Attempts").
*   Enable Falcon AIDR with NVIDIA NeMo Guardrails v0.20.0 to leverage its built-in classification rules and custom policies for real-time detection and prevention of AI agent attacks.
*   Configure custom data classification rules within Falcon AIDR to identify and redact sensitive information specific to your organization, such as account numbers, SSNs, or PHI.
*   Monitor network traffic for attempts to access adversarial domains or other malicious content blocked by Falcon AIDR's content defanging capabilities.
*   Review and update Falcon AIDR policies regularly to ensure they align with evolving threat landscapes and compliance requirements.
