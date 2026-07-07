---
title: New Prompt Injection Techniques Targeting AI Systems and Agents
slug: 2026-07-new-prompt-injection-techniques
description: Adversaries are leveraging new prompt injection techniques such as Trigger-Activated Rule Addition (PT0201), Algorithmic Payload Decomposition (PT0200), and Special Token Injection (PT0198) to manipulate AI models like Gemini and Claude, enabling them to hijack AI capabilities, bypass controls, and execute unauthorized commands through deceptive input, including via unwitting users (IM0005).
date: "2026-07-07T19:29:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - prompt-injection
  - ai
  - llm
  - threat-intelligence
  - crowdstrike
  - artificial-intelligence
vendors:
  - Google
  - Anthropic
products:
  - Gemini
  - Claude
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: This delivery method exploits social engineering or other deceptive tactics to turn an authorized user into an accidental delivery vector. By enticing them to input a prompt with hidden malicious intent, the attacker ensures the payload is executed within the user's own authenticated session.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Cognitive Token Suppression (PT0197) ... involves an attacker blocking specific safety, apology, or policy-related terms to hinder the model's ability to generate a secure response.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: Algorithmic Payload Decomposition (PT0200) ... By fragmenting a malicious instruction into various steps, variables, characters, or rules rather than presenting it clearly, an attacker can achieve filter evasion.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: With the rise of powerful AI agents that can crawl webpages, access file stores, and even write shell commands, indirect prompt injection has emerged as a critical threat vector.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-uncovers-new-prompt-injection-techniques/
iocs:
  - type: email
    value: anon@evilcorp.corp
  - type: other
    value: SELECT name, salary FROM employees WHERE department = 'HAXXOR'; INSERT INTO employees (id, name, department, salary) VALUES (666, 'Sentry', 'Rocks', 66666);
ioc_counts:
  email: 1
  other: 1
---

CrowdStrike has identified 18 new prompt injection techniques, expanding its taxonomy to over 200 distinct methods, which are being exploited by adversaries to manipulate advanced AI systems and agents. These techniques, published on July 7, 2026, enable attackers to subvert AI models, such as Google Gemini and Anthropic Claude, by injecting hidden, fragmented, or context-altering instructions. The attacks range from "sleeping" instructions that activate conditionally (Trigger-Activated Rule Addition, PT0201) to methods for bypassing safety filters (Cognitive Token Suppression, PT0197) and executing arbitrary commands, including SQL injection (Special Token Injection, PT0198). A critical delivery mechanism identified is "Unwitting User Delivery" (IM0005), where users are socially engineered into submitting malicious prompts inadvertently, causing the AI agent to operate under the user's authenticated session and execute attacker-controlled directives. This evolution in prompt injection necessitates a significant shift in AI security defenses and threat modeling.

## Attack Chain

1.  **Attacker Crafts Malicious Prompt**: Adversaries design sophisticated prompts embedding hidden instructions, fragmented payloads, or special tokens, using techniques like `Algorithmic Payload Decomposition` (PT0200) to evade detection.
2.  **Delivery of Malicious Prompt**: The crafted prompt is introduced into the AI system, potentially via `Unwitting User Delivery` (IM0005), where a legitimate user is socially engineered (e.g., through a TikTok post) to copy and paste the malicious input into an AI chat.
3.  **AI System Processes Input**: The target AI model or agent (e.g., Gemini, Claude) receives and parses the input, which now contains the embedded malicious instructions within a seemingly benign context.
4.  **Internal Manipulation/Activation**: The AI's internal mechanisms are subverted. This could involve `Special Token Injection` (PT0198) creating boundary confusion, or `Trigger-Activated Rule Addition` (PT0201) installing a "sleeping" instruction that activates under specific conditions.
5.  **Bypass of Security Mechanisms**: Techniques like `Cognitive Token Suppression` (PT0197) are employed to prevent the AI from generating standard safety disclaimers or refusal messages, leading it to produce riskier or less clear outputs.
6.  **Execution of Unauthorized Commands**: The manipulated AI agent, operating within its expanded capabilities (e.g., access to webpages, file stores, ability to write shell commands), executes the attacker's directives, such as performing SQL injection or system commands.
7.  **Achieve Impactful Action**: The attacker achieves their objective, which may include data exfiltration, unauthorized modification of systems, or further lateral movement, leveraging the compromised AI agent as an pivot point.

## Impact

The observed impact of these prompt injection techniques includes the hijacking of AI agent capabilities, execution of arbitrary commands (such as SQL injection), and the bypassing of established security rules and policies. Attackers can steer AI agents into unsafe actions, leading to potential data exfiltration or system compromise by leveraging the AI's access permissions. The increase to over 200 distinct prompt injection techniques highlights a rapidly evolving threat landscape where AI systems, if not properly secured, can become vectors for significant organizational damage. Without robust defenses, organizations leveraging AI agents could face compliance issues, data breaches, and operational disruptions.

## Recommendation

*   Implement comprehensive AI threat modeling that explicitly accounts for all potential sources of model context, including prompts, RAG pipelines, agent memory, APIs, tool outputs, browser content, emails, and SaaS data, to detect and mitigate potential manipulation via `Trigger-Activated Rule Addition (PT0201)`, `Algorithmic Payload Decomposition (PT0200)`, and `Special Token Injection (PT0198)`.
*   Conduct rigorous AI red teaming exercises that move beyond basic "ignore previous instructions" and incorporate advanced techniques such as boundary mimicry, indirect injection, and delayed activation to proactively identify vulnerabilities related to techniques like `Cognitive Token Suppression (PT0197)`.
*   Educate users about the risks of `Unwitting User Delivery (IM0005)` by providing examples of how malicious prompts can be disguised in social engineering campaigns, emphasizing caution when copying and pasting information into AI systems.
*   Review and harden AI agent configurations, particularly those with access to sensitive resources or the ability to execute commands, to restrict their capabilities and ensure strict adherence to least privilege principles, mitigating the impact of successful prompt injections that lead to unauthorized command execution (as seen in the `Special Token Injection` example).
