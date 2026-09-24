---
title: Tracking Storm-2570 Ransomware Affiliate Tradecraft
slug: 2026-09-storm-2570-tradecraft
description: Storm-2570 is a persistent ransomware affiliate that uses standardized post-compromise tooling across multiple RaaS ecosystems to conduct lateral movement and exfiltration.
date: "2026-09-24T20:11:13Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Storm-2570
tags:
  - ransomware
  - rmm-abuse
  - tunneling
  - post-compromise
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1219
    technique_name: Remote Access Software
    evidence: Storm-2570 frequently uses MeshAgent, Atera, and other RMM tools to maintain persistence.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1572
    technique_name: Protocol Tunneling
    evidence: Storm-2570 pairs remote access tooling with tunneling utilities such as Cloudflared.exe to create resilient outbound access paths.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: The actor uses NetScan, Nmap, and network scripts to perform discovery and reconnaissance.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003.003
    technique_name: NTDS
    evidence: Storm-2570 used ntdsutil for credential dumping.
    confidence_band: high
rules:
  - title: Detect Suspicious Renaming of MeshAgent
    description: Detects MeshAgent RMM binaries renamed with organization-specific tags to masquerade as legitimate services.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1036
    data_sources:
      - process_creation
      - windows
  - title: Detect Cloudflared Tunnel Service Installation
    description: Detects the creation of a Cloudflared service for persistent outbound tunneling.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1572
    data_sources:
      - process_creation
      - windows
rules_count: 2
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rules for RMM and tunnel discovery
      owner: Detection Engineering
      due: 48h
      evidence: Source-identified recurring use of RMM and tunneling tools
  hunt_leads:
    - lead: Search for unauthorized RMM agent execution
      technique_id: T1219
      data_needed:
        - Process creation logs showing Atera, MeshAgent, or ScreenConnect
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source identifies these as primary tools used by the actor
  mitigation_plan:
    - priority: immediate
      action: Restrict outbound communication for tunneling utilities
      owner: IT Operations
      addresses: T1572
      evidence: Source identifies Cloudflared and ngrok as persistence tools
---

Storm-2570 is a ransomware affiliate active since April 2025 that operates across multiple Ransomware-as-a-Service (RaaS) ecosystems, including Qilin, DragonForce, Anubis, and BERT. Microsoft Threat Intelligence analysis reveals that Storm-2570 maintains highly consistent post-compromise tradecraft regardless of the ransomware payload ultimately deployed. The actor relies heavily on the abuse of legitimate Remote Monitoring and Management (RMM) tools and tunneling utilities to maintain persistent access, perform reconnaissance, and facilitate data exfiltration.

By focusing on uniform behaviors - such as the unauthorized deployment of RMM agents, the creation of persistent tunnels, and the use of specific discovery and credential dumping utilities - defenders can detect and disrupt this actor's activity in the early stages of the intrusion. This cross-ecosystem consistency demonstrates that tracking ransomware threats by payload alone is insufficient for identifying and mitigating persistent affiliates. Storm-2570 has targeted organizations across various sectors, including healthcare, government, finance, and critical manufacturing, in multiple countries including the United States, United Kingdom, and Canada.

## Attack Chain

1. Initial access is established through unidentified vectors, followed by hands-on-keyboard activity to gain a foothold.
2. Deployment of RMM tools, such as MeshAgent, AteraAgent, or Remotely_Agent, often renamed to mimic legitimate organizational services.
3. Execution of discovery tools, including NetScan, Nmap, and network batch scripts, to map the environment and identify domain assets.
4. Credential access activities, including the use of ntdsutil for dumping Active Directory databases.
5. Lateral movement via PsExec, Impacket, or RDP, utilizing administrative credentials harvested during the discovery phase.
6. Establishment of persistent outbound communication channels using tunneling utilities such as Cloudflared or ngrok to maintain access and bypass inbound firewall controls.
7. Data collection and exfiltration using utilities like s5cmd or Rclone to move sensitive data to attacker-controlled cloud storage.
8. Deployment of ransomware (e.g., Qilin, DragonForce, Anubis, or BERT) to execute the final objective of encryption and extortion.

## Impact

Successful compromise by Storm-2570 results in the theft of sensitive organizational data, deployment of ransomware, and significant operational disruption. The actor has successfully targeted critical sectors including healthcare, government services, and critical manufacturing, demonstrating the potential for broad socioeconomic impact. By rotating between multiple ransomware ecosystems, Storm-2570 ensures flexibility in their monetization strategy, making them a consistent and dangerous threat to enterprise networks.

## Recommendation

- Enable process-creation logging (e.g., Sysmon Event ID 1) to monitor for the execution of RMM tools and discovery utilities listed in this brief.
- Implement a policy to allowlist or restrict the installation of unauthorized remote access software, specifically targeting known RMM tools like MeshAgent, Atera, and ScreenConnect.
- Monitor for anomalous outbound network connections associated with tunneling utilities like Cloudflared.exe and ngrok; restrict these tools to only known, authorized business processes.
- Audit administrative credential usage and restrict the use of tools like ntdsutil and PsExec to authorized system management accounts.
- Deploy the Sigma rules below to detect unauthorized renaming of RMM binaries and suspicious tunnel creation.
