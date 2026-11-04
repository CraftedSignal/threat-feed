---
brief_id: brief-2026-11-04-binance-heist
event_id: brief-2026-11-04-binance-heist
revision: 1
activity_at: "2026-11-04T11:00:05Z"
title: 'Binance: Security Incident Involving Compromised Engineering Systems'
slug: 2026-11-binance-heist
description: Binance reported a theft of $6.34 billion following a months-long campaign involving the compromise of three engineers' computers through a tampered software installation and a fake job recruitment process. The FBI has attributed the activity to the North Korean state-sponsored group TraderTraitor.
date: "2026-11-04T11:00:05Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - TraderTraitor
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.securityweek.com/rigged-coding-assignment-abused-ai-tool-opened-path-to-6-billion-binance-heist/
  observed_at: "2026-10-29T00:00:00Z"
  confidence: high
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: likely
tags:
  - financial-crime
  - social-engineering
  - crypto-theft
  - nation-state
vendors:
  - Binance
references:
  - https://www.securityweek.com/rigged-coding-assignment-abused-ai-tool-opened-path-to-6-billion-binance-heist/
---

Binance identified that attackers gained access to wallet signing systems via a campaign targeting its engineering staff. The intrusion utilized:
1. A tampered Homebrew installation downloaded by an engineer seeking an AI coding tool.
2. A fraudulent job recruitment process targeting a second engineer, which involved a fake HR representative and the delivery of a malicious coding assignment. 
3. Use of an internal AI tool by attackers to gain control over systems belonging to other engineers.

Attackers exploited unauthorized access to an internal wallet signing service to move assets and abused the Ethereum EIP-7702 mechanism to gain partial execution rights over hot wallets. Approximately $2.85 billion of the stolen assets have been frozen or intercepted.
