---
title: Lazarus Group Targeting AI Models to Enhance Cryptocurrency Theft
slug: 2026-05-lazarus-ai-targeting
description: The Lazarus Group is targeting AI models through supply chain attacks, contractor misuse, and fraudulent hiring to improve their ability to steal cryptocurrency and fund weapons programs.
date: "2026-05-02T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Lazarus Group
  - HIDDEN COBRA
  - LABYRINTH CHOLLIMA
  - Diamond Sleet
  - Zinc
tags:
  - lazarus
  - cryptocurrency
  - ai
  - supply-chain
  - north-korea
vendors:
  - Anthropic
  - LinkedIn
  - Bybit
products:
  - Claude Mythos
  - Safe{Wallet}
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Supply Chain Compromise
references:
  - https://www.recordedfuture.com/blog/lazarus-does-not-need-agi
  - https://www.bloomberg.com/news/articles/2026-04-21/anthropic-s-mythos-model-is-being-accessed-by-unauthorized-users
  - https://www.anthropic.com/project/glasswing
  - https://www.recordedfuture.com/research/crypto-country-north-koreas-targeting-cryptocurrency
  - https://www.state.gov/releases/office-of-the-spokesperson/2025/10/joint-statement-of-the-multilateral-sanctions-monitoring-team-msmt-on-the-report-covering-dprk-cyber-and-it-worker-activities
  - https://www.state.gov/releases/office-of-the-spokesperson/2026/01/the-democratic-peoples-republic-of-koreas-violations-and-evasions-of-un-sanctions-through-cyber-and-it-worker-activities/
  - https://www.amazon.com/Lazarus-Heist-Hollywood-Finance-Inside/dp/024155425X
  - https://www.fbi.gov/investigate/cyber/alerts/2025/north-korea-responsible-for-1-5-billion-bybit-hack
  - https://fortune.com/crypto/2025/03/04/north-korea-bybit-hack-ethereum-safe-dprk-lazarus-group-tradertraitor/
  - https://www.recordedfuture.com/research/inside-the-scam-north-koreas-it-worker-threat
  - https://intelligence2risk.substack.com/p/digital-supply-chain-breach
rules:
  - title: Detect Suspicious Bybit Activity
    description: Detects potentially malicious activity related to Bybit, possibly indicating reconnaissance or post-compromise activity.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1598
    data_sources:
      - network_connection
      - windows
  - title: Detect Suspicious LinkedIn Activity Associated with IT Contractors
    description: Detects suspicious activity related to LinkedIn, possibly indicating reconnaissance for fraudulent hiring schemes targeting IT contractors.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1598
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Recorded Future reported in April 2026 that the Lazarus Group and other DPRK-linked actors are actively targeting AI models, such as Anthropic's Claude Mythos, to enhance their cryptocurrency theft operations. The group employs various methods, including exploiting vulnerabilities in third-party contractor environments, fraudulent hiring schemes using fake developer personas on GitHub and LinkedIn, and supply chain attacks like the March 2026 LiteLLM compromise. These efforts aim to improve the efficiency of reconnaissance, social engineering, credential harvesting, and lateral movement during crypto exchange intrusions. The ultimate goal is to increase the amount of cryptocurrency stolen, which is then used to fund North Korea's weapons programs. This poses a significant threat because even a modest productivity gain in these operations can lead to substantially higher revenues for the DPRK regime.

## Attack Chain

1. **Initial Reconnaissance:** The attacker performs reconnaissance on targeted crypto exchanges and AI model providers using open-source intelligence and social media platforms like GitHub and LinkedIn to identify potential targets, including system administrators and developers.
2. **Social Engineering & Phishing:** The attacker crafts spear-phishing emails or fraudulent job offers, impersonating legitimate companies, to target employees at third-party vendors or crypto exchanges, aiming to harvest credentials.
3. **Credential Harvesting:** The attacker uses phishing campaigns and social engineering to harvest credentials, potentially employing AI tools to create more convincing fake personas or phishing emails.
4. **Initial Access:** Using stolen or synthetic credentials, the attacker gains initial access to a third-party vendor's system or directly into the target crypto exchange's network. This could involve accessing a cloud-based AI model like Claude Mythos via a compromised contractor account.
5. **Lateral Movement:** Once inside the network, the attacker performs lateral movement, leveraging compromised accounts and exploiting internal vulnerabilities to gain access to sensitive systems, such as Safe{Wallet} systems.
6. **Key Extraction:** The attacker focuses on extracting private keys and other sensitive information necessary to access and transfer cryptocurrency.
7. **Cryptocurrency Theft:** Using the stolen keys, the attacker initiates unauthorized cryptocurrency transfers from the exchange's wallets to attacker-controlled accounts.
8. **Money Laundering:** The stolen cryptocurrency is laundered through various mixing services and exchanges to obfuscate the source of funds and convert it into usable currency.

## Impact

The Lazarus Group's successful cryptocurrency heists have resulted in billions of dollars stolen, with estimates reaching over $2 billion in 2025 alone. These funds are directly used to finance North Korea's WMD and ballistic missile programs, undermining international sanctions and posing a significant national security threat. The attacks targeting AI models could lead to more efficient and sophisticated cyberattacks, further exacerbating the problem and increasing the financial resources available for weapons development. Bybit was one victim of these attacks, losing approximately $1.5 billion in virtual assets.

## Recommendation

*   Implement behavioral monitoring and least-privilege access controls for third-party vendors to mitigate the risk of contractor misuse, as highlighted in the Mythos incident.
*   Enhance identity verification processes during hiring, including in-person interviews, to prevent fraudulent hiring schemes, as detailed in the *Inside the Scam* report.
*   Monitor build-pipeline integrity and dependencies to defend against supply chain compromises, referencing the TeamPCP LiteLLM compromise.
*   Deploy the Sigma rule "Detect Suspicious Bybit Activity" to monitor for potential malicious activity targeting the Bybit exchange.
*   Implement telemetry and canaries within AI preview infrastructure to detect unauthorized access attempts, as recommended by Recorded Future.
