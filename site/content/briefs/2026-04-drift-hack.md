---
title: Drift Protocol $280M Crypto Theft Linked to North Korean Hackers
slug: 2026-04-drift-hack
description: The Drift Protocol suffered a $280 million crypto theft orchestrated by North Korean hackers who spent six months building an in-person operational presence within the Drift ecosystem, engaging with contributors at crypto conferences and via Telegram.
date: "2026-04-06T16:35:39Z"
type: threat
types:
  - threat
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

On April 1st, 2026, the Solana-based trading platform, Drift Protocol, experienced a sophisticated attack resulting in the theft of over $280 million. Investigations by Elliptic and TRM Labs point to North Korean hackers, possibly UNC4736 (also known as AppleJeus and Labyrinth Chollima), a threat actor previously linked to Lazarus. The attackers cultivated a presence within the Drift ecosystem over six months, posing as a quantitative firm. They approached Drift contributors in person at multiple crypto conferences, building trust and rapport. Communications continued via Telegram, where they discussed trading strategies and potential vault integrations, demonstrating technical proficiency and familiarity with Drift's operations. The Telegram group was deleted immediately after the theft.

## Attack Chain

1. **Initial Reconnaissance:** The threat actors posed as a quantitative firm to gather information about Drift Protocol and its contributors.
2. **In-Person Engagement:** The actors attended multiple crypto conferences, engaging with specific Drift contributors.
3. **Relationship Building:** They communicated with targets via Telegram, discussing trading strategies and potential vault integrations.
4. **Potential Compromise:** Two contributors were potentially compromised via a malicious code repository exploiting a VSCode/Cursor vulnerability allowing silent code execution, or via a malicious TestFlight application presented as a wallet product.
5. **Privilege Escalation:** The attack allowed the hijacking of the Security Council administrative powers.
6. **Asset Draining:** The attackers drained user assets in approximately 12 minutes.
7. **Data Removal:** The Telegram group used for engaging contributors was deleted immediately after the theft.
8. **Funds Laundering:** The stolen funds were likely transferred to attacker-controlled wallets and prepared for laundering, though the wallets have been flagged across exchanges and bridge operators.

## Impact

The Drift Protocol suffered a loss of over $280 million, impacting users of the Solana-based trading platform. All Drift Protocol functions remain frozen, and the compromised wallets have been removed from the multisig process. The incident highlights the risks associated with social engineering and the importance of verifying the identities of individuals and organizations interacting with critical infrastructure. The attack has also raised concerns about the security practices within the cryptocurrency sector.

## Recommendation

*   Monitor for unusual network activity and potential exploitation of VSCode/Cursor vulnerabilities via `process_creation` and `network_connection` logs using the "Detect Suspicious VSCode Code Execution" Sigma rule.
*   Monitor for suspicious applications installed via TestFlight, especially those presented as wallet products, using `file_event` logs and the "Detect Suspicious TestFlight Application Installation" Sigma rule.
*   Implement strict identity verification procedures for individuals and organizations interacting with sensitive systems and data.
*   Educate employees about social engineering tactics and the risks of interacting with unknown individuals or organizations.
