---
title: Jade Sleet Targets DevOps Engineers with FLATROOF and ROOFDECK Backdoors
slug: 2026-09-jade-sleet-backdoors
description: The North Korean threat actor Jade Sleet is conducting supply-chain attacks against DevOps engineers via malicious Terraform configurations that deploy Rust-based macOS backdoors.
date: "2026-09-21T06:16:05Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Jade Sleet
tags:
  - supply-chain
  - macos
  - malware
  - social-engineering
  - jade-sleet
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The campaign employs social engineering using job interview lures, a common tactic adopted by multiple North Korean threat actors.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: ROOFDECK... capable of... establishing persistence via Launch Agents
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: FLATROOF, a backdoor that uses Telegram for command-and-control (C2)
    confidence_band: high
references:
  - https://thehackernews.com/2026/09/jade-sleet-linked-to-indian-it-provider.html
iocs:
  - type: domain
    value: registry.hashicorp-aws.com
ioc_counts:
  domain: 1
rules:
  - title: Detect Suspicious macOS Launch Agent Creation
    description: Detects the creation of new Launch Agents, a technique used by ROOFDECK for persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - macos
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block registry.hashicorp-aws.com at DNS and egress proxies.
      owner: SOC
      due: 24h
      evidence: Source explicitly identifies as malicious Terraform registry domain.
  hunt_leads:
    - lead: Search for instances of '.terraform.lock.hcl' files being accessed or modified in user home directories.
      technique_id: T1195
      data_needed:
        - File integrity monitoring or process-level file access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source identifies weaponized Terraform lock files as the delivery vector.
  mitigation_plan:
    - priority: immediate
      action: Review developer workstation file integrity and audit recent 'terraform init' execution history.
      owner: IT Operations
      addresses: Supply chain attack
      evidence: Source notes developer endpoints are the central focus of the defense.
---

Jade Sleet, a North Korean threat actor also known as PUKCHONG, Slow Pisces, TraderTraitor, and UNC4899, has been linked to the compromise of an Indian IT services provider. The campaign targets developers in the DevOps and cryptocurrency sectors using sophisticated social engineering lures presented as job interview opportunities. The adversary distributes weaponized GitHub repositories containing malicious Terraform dependency lock files ('.terraform.lock.hcl'). When developers execute 'terraform init', these files force the platform to download and execute attacker-controlled modules from malicious registry domains.

Following initial access, the attackers deploy two Rust-based macOS implants: FLATROOF (Gaslight), which utilizes Telegram for C2 and browser data theft, and ROOFDECK, which leverages the Nostr protocol for decentralized C2, lateral movement, and persistence via Launch Agents. These tools are designed to target Apple Silicon architectures and implement complex evasion techniques, including the use of updated binaries that strip symbols to circumvent detection.

## Attack Chain

1. Attacker establishes contact with a target developer via social engineering lures posing as a job interview opportunity.
2. Target is directed to a malicious GitHub repository (e.g., 'terraform-candidate-repo') containing a weaponized '.terraform.lock.hcl' file.
3. Developer executes 'terraform init' in their local environment, triggering the download of malicious modules from 'registry.hashicorp-aws[.]com'.
4. The malicious modules execute on the developer's macOS machine, establishing the initial foothold.
5. Attacker deploys FLATROOF for reconnaissance, capturing browser data, keychain credentials, and shell histories.
6. Attacker deploys ROOFDECK to establish persistent C2 via Launch Agents, signed with a private key to verify command integrity.
7. Attacker uses ROOFDECK to perform lateral movement and exfiltrate sensitive cloud, pipeline, and source code credentials.

## Impact

Successful compromise allows the actor to gain deep access into corporate DevOps environments, source code pipelines, and cloud infrastructure. Victims are typically individual engineers, but the final objective involves credential exfiltration and unauthorized access to the target organization's sensitive technical assets. Previous activity by this group has resulted in multi-million dollar cryptocurrency thefts and supply chain compromises.

## Recommendation

1. Block the domain 'registry.hashicorp-aws[.]com' at the DNS and proxy level.
2. Implement strict monitoring for 'terraform init' commands originating from non-authorized directories or execution contexts.
3. Deploy detection for the creation of unauthorized Launch Agents on macOS endpoints using the Sigma rule provided below.
4. Educate developers on the risks of executing 'terraform init' within untrusted repositories and verify the hash integrity of dependencies.
