---
brief_id: brief-2026-11-01-tradertraitor-binance
event_id: brief-2026-11-01-tradertraitor-binance
revision: 4
activity_at: "2026-11-04T17:09:57Z"
revision_history:
  - revision: 2
    at: "2026-11-02T09:24:19Z"
    checksum: sha256:a59ce1e20e0797dd80fa7b4b1b5b58f6857a4641f8dad352eb29788131fd1b4d
    summary: exploited:true
    changed_fields:
      - claim_state
      - exploitation_evidence
      - lastmod
      - references
      - updates
    source_urls:
      - https://therecord.media/fbi-blames-tradertraitor-for-binance-hack
  - revision: 3
    at: "2026-11-03T18:18:07Z"
    checksum: sha256:7b0f04b74a22fb0e284df096acafe5e79fdb6144eeedba378649975486436515
    summary: added coverage for internal wallet signing service +1 products
    changed_fields:
      - action_plan
      - affected_products
      - content
      - lastmod
      - references
      - summary
      - title
      - ttps
      - updates
    source_urls:
      - https://thehackernews.com/2026/11/binance-reveals-how-fake-job-interviews.html
  - revision: 4
    at: "2026-11-04T17:09:57Z"
    checksum: sha256:e1297dc349bbfa57aa900d30b7719eaff51ec8c66cb87ead462b5484c0e84536
    summary: added coverage for Binance Wallet
    changed_fields:
      - action_plan
      - affected_products
      - content
      - lastmod
      - priority_signals
      - references
      - summary
      - title
      - ttps
      - updates
    source_urls:
      - https://arstechnica.com/information-technology/2026/11/binance-says-hackers-who-stole-billions-in-crypto-spent-months-planning-heist/
title: 'Binance: TraderTraitor multi-stage campaign targeting engineering infrastructure'
slug: 2026-11-tradertraitor-binance
description: The North Korean threat actor TraderTraitor compromised multiple Binance engineers through social engineering and supply-chain attacks to infiltrate wallet signing services and drain assets via unauthorized EIP-7702 smart contract delegations.
date: "2026-11-01T08:57:56Z"
lastmod: "2026-11-04T17:09:21Z"
type: threat
claim_state: <nil>
types:
  - threat
severities:
  - critical
actors:
  - TraderTraitor
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://therecord.media/fbi-blames-tradertraitor-for-binance-hack
  observed_at: "2026-11-02T00:00:00Z"
  confidence: medium
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: almost certain
qa_status:
  verdict: pass
tags:
  - cryptocurrency
  - financial-crime
  - nation-state
  - social-engineering
  - supply-chain
vendors:
  - Binance
  - HashiCorp
products:
  - Binance
  - Terraform
  - internal wallet signing service
  - internal AI tooling
  - Binance Wallet
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566.001
    technique_name: Spearphishing Attachment
    evidence: TraderTraitor's modus operandi employs recruitment-themed lures as a pretext to convince victims to run malicious code.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Unix Shell
    evidence: The poisoned Terraform provider is used to deliver a Bash loader that selects and downloads malware.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1195.002
    technique_name: Compromise Software Supply Chain
    evidence: The activity once again demonstrates how North Korean threat actors continue to abuse trusted developer workflows through trojanized Terraform providers.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    subtechnique_id: T1566.003
    subtechnique_name: Spearphishing via Service
    evidence: The second part of the attack occurred in September 2026, with the threat actor contacting another engineer (named "Engineer B") via a legitimate job-hunting platform by disguising themselves as a Project Director.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    subtechnique_id: T1204.002
    subtechnique_name: Malicious File
    evidence: Engineer B was instructed to download an 'assignment' containing a malicious code repository onto his work computer.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: On 29 October between 17:15 and 19:56, the attacker logged onto Software Engineer C's computer, used the credentials stolen from Wallet DevOps Engineer A, deployed a container, and triggered a malicious script.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    subtechnique_id: T1566.002
    subtechnique_name: Spearphishing Link
    evidence: In September, a separate engineer received messages through a legitimate job-hunting platform he was using.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1199
    technique_name: Trusted Relationship
    evidence: the attacker used that mechanism [EIP-7702] to give an attacker-controlled smart contract partial execution rights over a Binance hot wallet.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
    subtechnique_id: T1574.002
    subtechnique_name: DLL Side-Loading
    evidence: The malware employed sophisticated obfuscation and evasion techniques, including replacing a legitimate development tool component with a malicious version.
    confidence_band: high
references:
  - https://thehackernews.com/2026/11/fbi-links-north-koreas-tradertraitor-to.html
  - https://therecord.media/fbi-blames-tradertraitor-for-binance-hack
  - https://www.securityweek.com/fbi-flags-over-600-addresses-tied-to-north-koreas-binance-heist/
  - https://thehackernews.com/2026/11/binance-reveals-how-fake-job-interviews.html
  - https://arstechnica.com/information-technology/2026/11/binance-says-hackers-who-stole-billions-in-crypto-spent-months-planning-heist/
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Audit environment for the use of non-official or unvetted Terraform providers.
      owner: IT Operations
      due: 48h
      evidence: The poisoned Terraform provider is used to deliver a Bash loader.
    - action: Review and audit logs for unauthorized container deployments or non-standard credential usage in CI/CD environments.
      owner: SOC
      due: 24h
      evidence: The attacker logged onto Software Engineer C's computer, used the credentials stolen from Wallet DevOps Engineer A, deployed a container, and triggered a malicious script.
    - action: Audit and revoke any unrecognized EIP-7702 delegations on all enterprise-managed hot wallets.
      owner: Security Operations
      due: 24h
      evidence: The malicious EIP-7702 authorizations existed on-chain and operated independently of Binance’s normal withdrawal infrastructure.
  hunt_leads:
    - lead: Hunt for suspicious Bash execution originating from Terraform-related processes or directories.
      technique_id: T1059.004
      data_needed:
        - Process creation logs
        - Command line arguments
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The poisoned Terraform provider is used to deliver a Bash loader.
    - lead: Search for unauthorized or unusual container image deployments in production/wallet infrastructure.
      technique_id: T1611
      data_needed:
        - Container orchestration logs (e.g., Kubernetes API server logs)
        - CI/CD pipeline execution logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The attacker... deployed a container, and triggered a malicious script to launch the attack.
    - lead: Identify unusual internal AI tool usage by engineering accounts, specifically regarding requests to access deployment tokens or signing services.
      technique_id: T1078
      data_needed:
        - Internal AI tool access logs
        - Container deployment audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: On October 20, the attackers used the compromised engineer’s computer and an internal AI tool to take control of two other engineer devices.
  mitigation_plan:
    - priority: immediate
      action: Implement allow-listing for Terraform providers and disable dynamic loading of providers from untrusted registries.
      owner: IT Operations
      addresses: Terraform supply chain compromise
      evidence: The activity once again demonstrates how North Korean threat actors continue to abuse trusted developer workflows through trojanized Terraform providers.
    - priority: immediate
      action: Implement code-signing verification for all internally used development tools and third-party binaries.
      owner: IT Operations
      addresses: Supply chain compromise via trojanized development tools
      evidence: In June, an engineer downloaded a tampered version of Homebrew.
updates:
  - at: "2026-11-02T09:22:22Z"
    level: L3
    summary: exploited:true
    sources:
      - therecord
    source_urls:
      - https://therecord.media/fbi-blames-tradertraitor-for-binance-hack
  - at: "2026-11-03T18:17:24Z"
    level: L1
    summary: added coverage for internal wallet signing service +1 products
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/11/binance-reveals-how-fake-job-interviews.html
  - at: "2026-11-04T17:09:21Z"
    level: L1
    summary: added coverage for Binance Wallet
    sources:
      - ars-security
    source_urls:
      - https://arstechnica.com/information-technology/2026/11/binance-says-hackers-who-stole-billions-in-crypto-spent-months-planning-heist/
---

Binance confirmed a sophisticated, multi-stage campaign lasting from June 2026 to late October 2026, attributed to the North Korean threat actor TraderTraitor. The attackers successfully compromised engineering endpoints using trojanized software and fake recruitment schemes. The campaign culminated in the exploitation of internal AI tools and wallet signing services to bypass standard security controls, resulting in the movement of significant cryptocurrency assets. Notably, the attackers established independent persistence on-chain by exploiting Ethereum's EIP-7702 authorization mechanism, which allowed them to delegate hot wallet execution rights to attacker-controlled smart contracts, effectively bypassing standard withdrawal suspension measures.

## Attack Chain
1. Initial access via a compromised, trojanized Homebrew installation on an engineer's laptop.
2. Reconnaissance of team roles and infrastructure via the compromised endpoint.
3. Further compromise of a second engineer via social engineering (fake job interviews and malware-laced "assignment" code).
4. Lateral movement using a compromised internal AI tool to take control of additional engineer devices.
5. Theft of credentials and access tokens from compromised devices, including a token granting container deployment access.
6. Unauthorized access to the internal Multi-Party Computation (MPC) wallet signing service.
7. Execution of 50 signing transactions to establish malicious EIP-7702 on-chain delegations for hot wallets.
8. Extraction of funds (SOL, OP, BTC) to attacker-controlled addresses, bypassing withdrawal freezes.

## Impact
The attackers targeted $6.34 billion in cryptocurrency assets. Binance successfully froze or intercepted $2.85 billion. The campaign involved the unauthorized use of the internal wallet signing service and the exploitation of the EIP-7702 mechanism on-chain.

## Recommendation
- Audit internal development environments for unauthorized modifications to package managers (e.g., Homebrew) and development tool components.
- Implement strict verification procedures for job recruitment communications, especially those involving external chat applications or requests to execute code from external repositories.
- Review access control policies for internal AI tooling and container orchestration platforms to enforce least privilege.
- Implement specialized on-chain monitoring to detect unauthorized delegation or permission changes related to EIP-7702 or similar smart contract authorization mechanisms.
- Conduct an immediate audit of all active on-chain authorizations for hot wallet services to identify and revoke any unauthorized smart contract delegations.
