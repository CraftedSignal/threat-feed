---
brief_id: brief-2026-11-02-volta-infostealer
event_id: brief-2026-11-02-volta-infostealer
revision: 1
activity_at: "2026-11-02T06:29:08Z"
title: VOLTA-AUTODOXER Infostealer Leverages LLMs for Victim Data Prioritization
slug: 2026-11-volta-infostealer
description: The VOLTA-AUTODOXER (VOLTA) Windows infostealer automates the triage of stolen credentials and sensitive data by sending serialized evidence bundles to LLMs via the OpenRouter API to rank victim monetization potential.
date: "2026-11-02T06:29:08Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source supported; telemetry needs environment-specific validation.
tags:
  - infostealer
  - ai-enabled-malware
  - credential-theft
  - telegram-c2
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Like other typical stealer families, VOLTA is equipped to harvest passwords and cookies from Chromium-based web browsers; data from Outlook profiles and Slack workspaces
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: Web Protocols
    evidence: Data exfiltration happens over Telegram at three different stages
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: To make this information more valuable, the malware uses stolen session access to search the victim's Gmail account for receipts
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1539
    technique_name: Steal Web Session Cookie
    evidence: VOLTA is equipped to harvest ... cookies from Chromium-based web browsers
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: VOLTA is equipped to harvest passwords ... from Chromium-based web browsers
    confidence_band: high
references:
  - https://thehackernews.com/2026/11/new-volta-infostealer-uses-claude.html
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block or monitor egress traffic to Telegram API domains and OpenRouter API endpoints
      owner: SOC
      due: 24h
      evidence: Data exfiltration happens over Telegram; AI analysis uses OpenRouter.
  hunt_leads:
    - lead: Search for processes attempting to access browser data directories followed by immediate external network calls to Telegram or OpenRouter.
      technique_id: T1005
      data_needed:
        - EDR process execution logs
        - Network connection logs (destination IPs/domains)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: VOLTA harvests data and serializes it for external AI analysis and C2 exfiltration.
---

VOLTA-AUTODOXER (aka VOLTA) is a Windows-based infostealer designed to offload data triage tasks to Large Language Models (LLMs). The malware harvests a wide array of sensitive data, including browser credentials, cookies, payment information, cryptocurrency wallet seeds, and session tokens for platforms like Discord, Telegram, and Steam. After collection, it serializes this data into an "evidence bundle" and routes it through the OpenRouter API to AI models - specifically Anthropic’s Claude, Moonshot AI’s Kimi, or Google’s Gemini - to generate a prioritized dossier on the victim, including a "WHAT THEY'RE WORTH" monetization assessment. Data exfiltration occurs in three stages via the Telegram messaging platform.

## Attack Chain

1. Initial infection and execution of the VOLTA-AUTODOXER binary on the Windows host.
2. Harvesting of local credentials, session tokens, and configuration files from web browsers, Outlook, Slack, and cloud-provider keys.
3. Enrichment of the stolen dataset by searching local Gmail caches for purchase receipts (e.g., Amazon, DoorDash, Uber Eats).
4. Serialization of the collected artifacts into a structured evidence bundle.
5. Transmission of the evidence bundle to an AI-model API (OpenRouter) using a system prompt designed to force the model into the role of a forensic intelligence analyst.
6. Exfiltration of the raw data, LLM-generated assessment, and enrichment evidence to the operator via Telegram.

## Impact

VOLTA enables operators to move beyond raw data collection to actionable, prioritized targeting. The use of AI for dossier generation provides immediate assessment of a victim's financial worth and security posture, which can significantly accelerate the effectiveness of subsequent phases like ransomware deployment or identity theft.

## Recommendation

- Monitor for unauthorized or suspicious outbound traffic to the OpenRouter API domain and Telegram API endpoints.
- Audit and restrict the use of unauthorized AI API keys or environment variables (e.g., OPENAI_API_KEY, though VOLTA uses OpenRouter, similar LLMjacking patterns apply) within enterprise environments.
- Implement endpoint detection and response (EDR) rules to monitor for common stealer behaviors: bulk file access in browser/application profiles, unusual process spawning, and connections to messaging-based C2 services.
- Enforce policies to prevent the storage of plaintext credentials or long-lived session tokens on local disk.
