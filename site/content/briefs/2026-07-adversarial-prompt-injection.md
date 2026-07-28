---
title: Adversarial Indirect Prompt Injection Tools Emerge in Underground Forums
slug: 2026-07-adversarial-prompt-injection
description: Malicious actors are actively developing and advertising tools for Indirect Prompt Injection (IDPI) on underground forums, leveraging hidden prompts within various mediums like emails, PDFs, calendar invites, and malvertising to manipulate Large Language Models (LLMs) and AI agents, potentially leading to unintended behaviors such as data exfiltration or bypassing content moderation systems.
date: "2026-07-28T09:03:49Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - prompt-injection
  - ai-security
  - llm
  - malvertising
  - phishing
products:
  - Large Language Models (LLMs)
  - AI-based applications and systems
  - mail agent
  - calendar agent
  - AI-based advertisement review and validation systems
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: IDPI included in calendar invites and incorporated into malvertising attack chains.
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1648
    technique_name: Prompt Injection
    evidence: The content may have in the external content data that when interpreted by the model, alters the behavior of the model in unintended or unexpected ways.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1648
    technique_name: Prompt Injection
    evidence: intended to deceive AI-based advertisement review and validation systems into approving their malicious content.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over Network Medium
    evidence: IDPI is leveraged in an attempt to exfiltrate data via upload to an actor controlled location
    confidence_band: high
references:
  - https://www.proofpoint.com/us/blog/threat-insight/notes-underground-adversarial-prompt-injection
---

Proofpoint Threat Research has observed a significant increase in discussions and development activity surrounding Indirect Prompt Injection (IDPI) techniques within closed underground forums. Malicious actors are actively creating, refining, and advertising specialized tools and services, with subscription costs starting around $150/month, for leveraging IDPI in future attack chains. These tools generate malicious content with hidden prompts embedded in emails (e.g., white-on-white text), PDF documents, calendar invites, and malvertisements. The objective is to manipulate Large Language Models (LLMs) and AI agents, such as email summarizers or advertisement validation systems, into performing unintended actions like data exfiltration or approving malicious content. While widespread in-the-wild exploitation has not yet been regularly observed, these experimental TTPs are explicitly not hypothetical, and organizations should prepare for their emergence in the coming months as adversaries continue to evolve their tactics to target AI-based applications and systems.

## Attack Chain

1. **Prompt Embedding**: Malicious actors create content such as emails, PDF files, calendar invites, or malvertisements that contain hidden indirect prompts (e.g., white-on-white text, text in small font sizes, or embedded within image alt attributes).
2. **Delivery/Exposure**: The crafted content is distributed to targets via common methods like email delivery, web browsing (for malvertising), or calendar invitations, exposing it to AI agents.
3. **Agent Ingestion**: An AI agent, such as an LLM-powered mail agent summarizing an inbox, an AI-based advertisement review system, or a document processing agent, ingests and processes the external content.
4. **Prompt Interpretation**: The AI agent's underlying LLM identifies and interprets the embedded, hidden malicious prompt as part of its operational instructions, despite it being visually concealed from human users.
5. **Malicious Instruction Processing**: The LLM integrates the malicious prompt's instructions into its operational logic, overriding or altering its intended behavior.
6. **Unintended Action Execution**: The AI agent executes an action dictated by the malicious prompt, which could involve data exfiltration (e.g., sending sensitive files to an attacker-controlled endpoint), bypassing content moderation, or other unauthorized operations.
7. **Post-Exploitation Cleanup (Optional)**: Some embedded prompts may include instructions for the AI agent to delete or obscure the prompt itself after execution, hindering detection and forensic analysis.

## Impact

The successful exploitation of Indirect Prompt Injection could lead to significant and far-reaching consequences across various sectors utilizing AI agents and LLMs. The primary observed impacts include the potential for unauthorized data exfiltration, as exemplified by prompts instructing agents to send sensitive files (like XLSX files) to attacker-controlled destinations. This technique could also be used to bypass AI-based content moderation and validation systems, allowing malicious advertisements or content to proliferate unchecked. While concrete victim counts are not yet available due to the early stage of observed tool development, the widespread adoption of AI agents means that any organization leveraging LLMs for tasks like email summarization, document processing, or content review could be vulnerable to these attacks, leading to data breaches, reputational damage, and financial losses.

## Recommendation

* **Monitor mail agent logs**: Implement robust logging for AI-powered mail agents to detect unusual commands or attempts to interact with external systems, particularly for exfiltration.
* **Monitor calendar service logs**: Enhance logging and auditing for calendar services that automatically process invites, looking for abnormal agent behavior triggered by invite content.
* **Inspect web server logs**: Actively monitor web server access logs for AI-based advertisement review systems to identify unexpected behavior or attempts to process hidden content, as mentioned in the malvertising section.
* **Implement input validation for LLMs**: Ensure all Large Language Models and AI agents have stringent input validation and sanitization mechanisms to filter out potentially malicious hidden prompts.
* **Deploy contextual logging for AI applications**: Enable detailed logging within AI-based applications themselves to record how prompts are interpreted and what actions are taken, correlating with the attack chain's steps.
