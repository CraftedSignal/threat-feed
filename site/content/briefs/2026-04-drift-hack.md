---
title: Drift Protocol $280M Crypto Theft Linked to North Korean Hackers
slug: 2026-04-drift-hack
description: The Drift Protocol suffered a $280 million crypto theft orchestrated by North Korean hackers who spent six months building an in-person operational presence within the Drift ecosystem, engaging with contributors at crypto conferences and via Telegram.
date: "2026-04-06T16:35:39Z"
severities:
  - critical
actors:
  - UNC4736 (Lazarus Group)
tags:
  - drift-protocol
  - crypto-theft
  - north-korea
  - unc4736
  - lazarus-group
  - social-engineering
  - supply-chain
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Drive-by Compromise
references:
  - https://www.bleepingcomputer.com/news/security/drift-280m-crypto-theft-linked-to-6-month-in-person-operation/
rules:
  - title: Detect Suspicious VSCode Code Execution
    description: Detects potential exploitation of VSCode/Cursor vulnerabilities leading to silent code execution.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious TestFlight Application Installation
    description: Detects potential installation of malicious applications via TestFlight.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - file_event
      - macos
rules_count: 2
---

On April 1st, 2026, the Solana-based trading platform, Drift Protocol, experienced a sophisticated attack resulting in the theft of over $280 million. Investigations by Elliptic and TRM Labs point to North Korean hackers, possibly UNC4736 (also known as AppleJeus and Labyrinth Chollima), a threat actor previously linked to Lazarus. The attackers cultivated a presence within the Drift ecosystem over six months, posing as a quantitative firm. They approached Drift contributors in person at…
