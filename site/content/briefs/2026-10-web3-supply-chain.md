---
title: Evolution of Web3-Based C2 in Cloud Supply Chain Attacks
slug: 2026-10-web3-supply-chain
description: North Korea-affiliated threat actors are leveraging Web3-based command-and-control infrastructure and open-source supply chain poisoning to extract high-privilege cloud credentials from developer environments and CI/CD pipelines.
date: "2026-10-07T22:32:09Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Alluring Pisces
tags:
  - supply-chain
  - cloud-security
  - C2
  - blockchain
  - DPRK
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195.002
    technique_name: 'Supply Chain Compromise: Compromise Software Dependencies'
    evidence: By poisoning open-source dependencies, threat actors bypass traditional authentication perimeters to harvest the following from developer endpoints and continuous integration/continuous deployment (CI/CD) pipelines.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1102.002
    technique_name: 'Web Service: Bidirectional Communication'
    evidence: Threat actors have systematically upgraded their command-and-control (C2) infrastructure to use Web3, also known as Web 3.0 or decentralized blockchain web architectures.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555.003
    technique_name: Credentials from Web Browsers
    evidence: It captures ephemeral cloud provider identity and access management (IAM) keys, CI/CD pipeline worker tokens and short-lived OIDC federation keys.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review CI/CD pipeline logs for build processes spawning unauthorized network connections to RPC endpoints.
      owner: SOC
      due: 24h
      evidence: Malware executes a preinstall script hook that downloads a custom Bun runtime to launch an obfuscated credential harvester.
  hunt_leads:
    - lead: Process creation from build hooks (npm preinstall, Rust build scripts) initiating outbound connections.
      technique_id: T1195.002
      data_needed:
        - Process creation logs
        - Network connection logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The worm executes a preinstall script hook that downloads a custom Bun runtime to launch an obfuscated credential harvester.
---

Unit 42 research details an evolution in threat actor C2 strategies, specifically focusing on the integration of Web3 and blockchain architectures to bypass traditional network defenses. This trend is heavily utilized by North Korea-affiliated actors, such as Alluring Pisces (also known as Sapphire Sleet or Midnight Neptune). These actors compromise open-source dependencies in the npm, Go, and Rust ecosystems to gain initial access to enterprise cloud environments. By injecting malicious code into packages like Axios, Mastra AI, and the Rust arrayref crate, attackers target developer workstations and CI/CD runners to scrape ephemeral cloud identity tokens, service account keys, and deployment secrets. The C2 infrastructure has moved from static endpoints to sophisticated blockchain-based resolution methods, including EtherHiding, TxDataHiding, and NullReceiver, which effectively hide C2 instructions within standard blockchain transactions to evade conventional network-based threat detection.

## Attack Chain

1. Attacker compromises a package maintainer's account or exploits an open-source registry to publish a backdoored dependency.
2. The target developer or CI/CD system resolves and installs the poisoned dependency, triggering preinstall or compilation hooks.
3. Malware executes within the build process or developer IDE, scanning memory and files for cloud IAM keys, service account credentials, and deployment secrets.
4. The loader initiates a C2 resolution process by performing JSON-RPC calls to public blockchains (e.g., Ethereum, TRON, or Binance Smart Chain).
5. The malware parses either smart contract state variables, transaction input data (calldata), or recipient address structures to identify the dynamic C2 IP or domain.
6. The malware establishes a connection to the retrieved C2 endpoint to exfiltrate the harvested cloud credentials.
7. Attacker uses the stolen high-privilege tokens to gain direct access to cloud management consoles and administrative APIs.

## Impact

The shift toward Web3-based supply chain attacks allows threat actors to maintain persistent access to highly privileged cloud environments while evading standard network monitoring. Successful compromises result in the theft of administrative identity keys, leading to potential full cloud account takeovers. Recent campaigns have targeted critical development dependencies, impacting organizations relying on modern CI/CD workflows and AI-assisted coding tools. The ability for attackers to dynamically update C2 infrastructure via blockchain transactions ensures long-term operational resilience for these campaigns.

## Recommendation

1. Evaluate the organizational necessity for blockchain or Web3 network connectivity; if not required, implement network-level egress blocks for known public blockchain RPC endpoints.
2. Deploy endpoint security controls to monitor and block suspicious process behavior originating from build hooks, such as unauthorized memory scanning or unexpected network connections from CI/CD runners.
3. Automate policy controls within CI/CD pipelines to restrict the use of non-approved or unvetted open-source dependencies.
4. Implement strict secret management practices, ensuring ephemeral cloud identity tokens are scoped with the minimum required permissions and short TTLs to limit the impact of credential theft.
