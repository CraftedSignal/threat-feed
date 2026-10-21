---
brief_id: brief-2026-10-21-ai-assisted-cybercrime
event_id: brief-2026-10-21-ai-assisted-cybercrime
revision: 1
activity_at: "2026-10-21T16:05:57Z"
title: 'BUGSTER Threat Actor: AI-Assisted Cybercrime'
slug: 2026-10-ai-assisted-cybercrime
description: A threat actor using the handle BUGSTER utilized the Hermes Agent framework and DeepSeek V4 to facilitate credential theft, database exfiltration, VoIP fraud planning, and Wi-Fi password cracking.
date: "2026-10-21T16:05:57Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - BUGSTER
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://unit42.paloaltonetworks.com/ai-assisted-cybercrime-analysis/
  observed_at: "2026-10-21T16:05:57Z"
  confidence: medium
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
references:
  - https://unit42.paloaltonetworks.com/ai-assisted-cybercrime-analysis/
iocs:
  - type: ip
    value: 162.243.3.92
  - type: ip
    value: 104.238.38.202
ioc_counts:
  ip: 2
---

Unit 42 investigated a threat actor identified as BUGSTER who weaponized AI assistants - specifically the Hermes Agent framework integrated with DeepSeek V4 - to coordinate multiple types of cybercrime. The actor operated with safety controls disabled in their AI tools.

Observed activities include:
- **Credential Theft and Data Exfiltration**: The actor utilized AI-generated reconnaissance to enumerate WordPress subdomains and REST APIs, leading to brute-force attacks and the successful exfiltration of a MongoDB database containing over 5,200 student and faculty records.
- **VoIP Fraud Planning**: The actor utilized AI bot profiles to acquire actionable knowledge on forming US-based LLCs, carrier access, and techniques for bypassing caller identity verification.
- **Wi-Fi Password Cracking**: The actor maintained automated pipelines to capture WPA authentication material from nearby access points for remote cracking.
- **Cryptocurrency Reconnaissance**: The actor scraped data on cryptocurrency holders for potential future targeting.

The investigation confirmed the actor's ability to execute these activities across diverse domains by leveraging AI as an expert advisor and task-automation tool.
