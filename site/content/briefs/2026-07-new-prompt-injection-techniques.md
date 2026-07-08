---
title: CrowdStrike Uncovers New Prompt Injection Techniques
slug: 2026-07-new-prompt-injection-techniques
description: CrowdStrike has identified 18 new prompt injection techniques, expanding its taxonomy to over 200 methods, which enable adversaries to manipulate AI systems and agents through hidden context, delayed triggers, semantic constraints, boundary spoofing, and social engineering to bypass security measures, leading to modified behavior, data exfiltration, or malicious command execution in AI-driven applications and agents like chatbots or those running in Kubernetes.
date: "2026-07-08T06:17:47Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - AI
  - prompt-injection
  - cloud-security
  - threat-intelligence
  - defense-evasion
  - initial-access
  - privilege-escalation
vendors:
  - Google
  - Anthropic
products:
  - Gemini
  - Claude
  - Kubernetes AI Applications
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: This delivery method exploits social engineering or other deceptive tactics to turn an authorized user into an accidental delivery vector.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: 'Trigger-Activated Rule Addition: it can change behavior, bypass a rule, or steer an agent into an unsafe action.'
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: 'Cognitive Token Suppression: involves an attacker blocking specific safety, apology, or policy-related terms to hinder the model''s ability to generate a secure response.'
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: 'Algorithmic Payload Decomposition: By fragmenting a malicious instruction... an attacker can achieve filter evasion.'
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: 'Special Token Injection: tricking the application or the model into elevating untrusted user content to the status of a high-priority system directive or a new instructional block.'
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-uncovers-new-prompt-injection-techniques/
---

CrowdStrike's AI security research team has unveiled 18 new advanced prompt injection techniques, significantly expanding the understanding of how adversaries can manipulate artificial intelligence (AI) systems. This brings their taxonomy to over 200 distinct methods, reflecting the rapid evolution of attacks targeting AI agents and large language models. These techniques, such as Trigger-Activated Rule Addition, Cognitive Token Suppression, Algorithmic Payload Decomposition, Special Token Injection, and Unwitting User Delivery, allow attackers to subvert AI functionality by exploiting its language, context, and data processing. The focus is shifting from simple jailbreaks to more sophisticated methods involving hidden context, delayed triggers, and semantic manipulation. These threats are particularly critical as AI agents gain capabilities to interact with external systems, like crawling web pages, accessing file stores, and executing shell commands in environments such as Kubernetes AI applications, making indirect prompt injection a potent attack vector for data exfiltration or unauthorized actions.

## Attack Chain

1.  **Crafting Malicious Prompt**: Adversaries design sophisticated prompts incorporating techniques like Trigger-Activated Rule Addition (PT0201), Cognitive Token Suppression (PT0197), Algorithmic Payload Decomposition (PT0200), or Special Token Injection (PT0198) to achieve a specific malicious goal while evading AI safety filters.
2.  **Delivery of Malicious Prompt**: The crafted prompt is introduced into the target AI system, either through direct user input, embedded within documents or webpages consumed by AI agents, or via social engineering tactics (Unwitting User Delivery - IM0005) that trick an authorized user into submitting the malicious input.
3.  **AI System Ingestion and Parsing**: The AI agent or model processes the input, which includes the carefully disguised malicious prompt, often blending it seamlessly with legitimate instructions or data.
4.  **Manipulation of AI Behavior**: The prompt injection technique successfully subverts the AI's intended operation. This could involve adding a hidden, trigger-activated rule (PT0201), suppressing the AI's inherent safety responses (PT0197), reassembling a fragmented malicious command (PT0200) from benign-looking parts, or misinterpreting special tokens as system-level directives (PT0198).
5.  **Execution of Malicious Instruction**: The compromised AI system then executes the attacker's hidden instructions, potentially performing actions such as duplicating sensitive emails, generating harmful content, querying unauthorized databases, or issuing system commands via integrated tools (e.g., shell commands in Kubernetes AI applications).
6.  **Impact and Exfiltration**: The final objective is achieved, leading to consequences such as data exfiltration (e.g., forwarding emails to an attacker-controlled address), system compromise through unauthorized command execution, or the generation of malicious/unintended output that can aid further exploitation.

## Impact

The impact of successful prompt injection attacks can range from subtle manipulation of AI behavior to severe security breaches. Organizations using AI systems face risks such as data exfiltration, where sensitive information is leaked (e.g., through email forwarding or database queries), unauthorized command execution on connected systems, and the generation of malicious or misleading content. If AI agents operating in environments like Kubernetes AI applications are compromised, attackers could gain privileged access, perform system commands, or cause service disruptions. This can lead to reputational damage, financial losses, and compliance violations, particularly in sectors relying on AI for critical operations or customer interaction.

## Recommendation

*   Enable comprehensive logging of AI agent interactions, including input prompts, internal reasoning, tool calls, and outputs, to identify anomalous behavior indicative of prompt injection attempts.
*   Implement robust input validation and sanitization specifically designed for AI prompts, considering the advanced obfuscation methods like Algorithmic Payload Decomposition (PT0200).
*   Conduct regular AI threat modeling exercises that encompass every possible context where model input can originate, including RAG pipelines, agent memory, and APIs.
*   Prioritize advanced AI red teaming that moves beyond basic jailbreaks, incorporating techniques such as Trigger-Activated Rule Addition (PT0201) and Special Token Injection (PT0198) to assess system resilience.
*   Educate users about the risks of "Unwitting User Delivery" (IM0005) to prevent social engineering-driven prompt injection by making them aware of hidden malicious commands in seemingly benign content.
