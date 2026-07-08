---
title: CrowdStrike Uncovers New Prompt Injection Techniques in AI Systems
slug: 2026-07-new-prompt-injection-techniques
description: CrowdStrike research has identified 18 new prompt injection techniques, including five detailed examples, which adversaries are leveraging to manipulate AI systems and agents, bypass safety mechanisms, and achieve filter evasion, posing a critical threat to AI security by allowing attackers to hijack AI capabilities for malicious actions such as data exfiltration or generating unsafe content.
date: "2026-07-08T06:46:05Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - prompt-injection
  - ai-security
  - machine-learning
  - defense-evasion
  - social-engineering
  - cloud
vendors:
  - Google
products:
  - AI agents
  - AI systems
  - language models
  - Kubernetes AI Applications
  - Gemini
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: This delivery method exploits social engineering or other deceptive tactics to turn an authorized user into an accidental delivery vector.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: By fragmenting a malicious instruction into various steps, variables, characters, or rules rather than presenting it clearly, an attacker can achieve filter evasion.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: this method involves an attacker blocking specific safety, apology, or policy-related terms to hinder the model's ability to generate a secure response.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: By mimicking these specific markers, attackers aim to induce boundary confusion, tricking the application or the model into elevating untrusted user content to the status of a high-priority system directive or a new instructional block.
    confidence_band: med
references:
  - https://www.crowdstrike.com/en-us/blog/crowdstrike-uncovers-new-prompt-injection-techniques/
---

CrowdStrike's AI security research team recently published findings on 18 newly identified prompt injection techniques, bringing their taxonomy to over 200 distinct methods. Published on July 07, 2026, this research highlights how adversaries are evolving their methods to manipulate sophisticated AI systems and agents beyond simple jailbreaks. The techniques described include hiding malicious instructions with delayed triggers (Trigger-Activated Rule Addition), circumventing safety mechanisms by suppressing refusal terms (Cognitive Token Suppression), fragmenting malicious payloads to evade filters (Algorithmic Payload Decomposition), and exploiting structural cues to elevate untrusted user content (Special Token Injection). Furthermore, the "Unwitting User Delivery" method outlines how social engineering can turn authorized users into vectors for delivering malicious prompts. These methods demonstrate a critical shift towards more sophisticated, indirect manipulation of AI, impacting AI agents that can crawl webpages, access file stores, and execute shell commands. This evolution necessitates a re-evaluation of AI threat modeling and red teaming to counter these advanced threats.

## Attack Chain

1.  An adversary crafts a sophisticated prompt containing hidden or fragmented malicious instructions designed to manipulate an AI system or agent.
2.  The adversary employs "Unwitting User Delivery (IM0005)" by leveraging social engineering (e.g., a deceptive social media post) to trick an authorized user into inputting the malicious prompt into an AI system within their authenticated session.
3.  The AI system or agent receives the crafted prompt, which may contain a "Trigger-Activated Rule Addition (PT0201)" – a dormant instruction set that remains inactive until a specific keyword, event, or condition is met.
4.  Alternatively, the prompt may utilize "Algorithmic Payload Decomposition (PT0200)" where the malicious instruction is broken down into seemingly benign components (e.g., variables, characters, rules) that the AI system is instructed to reassemble, thereby evading initial filters.
5.  The prompt might also include "Special Token Injection (PT0198)," mimicking the AI system's internal structural cues (e.g., <tool_call> tags) to confuse boundary distinctions and trick the model into treating untrusted user input as a high-priority system directive.
6.  Upon processing, these injection techniques allow the AI system to bypass its intended safety mechanisms, evade content filters, or interpret malicious instructions as legitimate commands.
7.  The AI's behavior is then altered, leading it to perform actions like forwarding sensitive emails to an attacker-controlled address or generating instructions for unsafe activities.
8.  Ultimately, the AI agent executes unauthorized commands, exfiltrates data, generates harmful content, or otherwise deviates from its intended, secure operation, achieving the adversary's objective.

## Impact

The identified prompt injection techniques enable adversaries to achieve significant impact by compromising the integrity and security of AI systems and agents. Successful exploitation can lead to the bypassing of safety mechanisms, filter evasion, and direct manipulation of AI behavior, potentially resulting in unauthorized data access (e.g., exfiltrating email data), execution of arbitrary commands (e.g., unauthorized SQL queries or shell commands if integrated with tool access), or the generation of harmful and unsafe content (e.g., instructions for 3-D printing a car with dangerous design flaws). The threat impacts any organization utilizing AI agents with access to internal systems, data, or external tools, turning these powerful AI capabilities into vectors for adversary objectives and eroding trust in AI deployments. The scope of targeting is broad, encompassing any organization that deploys or integrates AI systems or agents, as demonstrated by the mention of Gemini.

## Recommendation

*   Expand AI threat modeling and logging strategies to comprehensively cover all potential sources of model context, including prompts, files, RAG pipelines, agent memory, APIs, tool outputs, browser content, emails, and SaaS data, as explicitly detailed in this brief.
*   Enhance AI red teaming efforts to simulate advanced prompt injection techniques, including boundary mimicry, indirect injection, and delayed activation, as identified and described within this brief, to rigorously test existing detection and prevention controls.
*   Implement robust input validation and output filtering mechanisms for all AI agent interactions, with particular scrutiny for functions involving sensitive operations such as email sending or database queries, as illustrated by the examples in this brief.
