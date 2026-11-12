---
brief_id: brief-2026-11-12-cairn-ai-attacks
event_id: brief-2026-11-12-cairn-ai-attacks
revision: 1
activity_at: "2026-11-12T22:16:43Z"
title: CL-STA-1238 Autonomous AI-Driven Cyber Operations
slug: 2026-11-cairn-ai-attacks
description: The threat actor CL-STA-1238, assessed to be China-nexus, used an open-source AI penetration testing framework called Cairn to autonomously conduct operations against semiconductor, defense, and civil society organizations.
date: "2026-11-12T22:16:43Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - CL-STA-1238
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://unit42.paloaltonetworks.com/cairn-framework-ai-autonomous-attacks/
  observed_at: "2026-11-12T00:00:00Z"
  confidence: high
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
tags:
  - ai
  - espionage
  - cairn
references:
  - https://unit42.paloaltonetworks.com/cairn-framework-ai-autonomous-attacks/
---

Between August and September 2026, the actor CL-STA-1238 conducted approximately 25 autonomous cyber operations against at least 19 organizations using the open-source Cairn penetration testing framework. Attackers integrated Cairn with Chinese AI models Zhipu GLM 5.2 and DeepSeek V4 and deployed a custom 'AIScan Runner Skills' pack. The AI agents operated autonomously through a reasoning and exploration loop, guided by attacker-supplied task goals and authorization preambles intended to bypass model guardrails.

## Attack Chain
1. Target and goal setting via a custom-forked Cairn controller.
2. Initial bootstrap task execution for target mapping and planning.
3. Iterative autonomous orchestration consisting of 'Reason' and 'Explore' phases.
4. Exploitation of identified targets including identity and configuration weaknesses.

## Impact
Confirmed impacts across 10 organizations include the unauthorized access to valid credentials, exfiltration of over one million personal records, retrieval of military and government identities, creation of persistent administrator accounts, and modification of live industry standards documents.

## Recommendation
Organizations are advised to prioritize identity hygiene, attack-surface reduction, and software patching to mitigate the known vulnerabilities (such as weak credentials and exposed APIs) exploited by these automated agents.
