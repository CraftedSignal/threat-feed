---
title: Disruption of Sality P2P Botnet Infrastructure
slug: 2026-09-sality-takedown
description: International law enforcement successfully disrupted the long-standing Sality P2P botnet by leveraging peer list manipulation to sinkhole the network and isolate infected Windows hosts.
date: "2026-09-02T08:18:12Z"
type: advisory
types:
  - advisory
severities:
  - high
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: Web Protocols
    evidence: Sality-linked domains have been seized in the U.S. and Europe.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: Sality has been documented in the wild since 2003, featuring capabilities to infect and modify Windows executable files.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1573
    technique_name: Encrypted Channel
    evidence: Several variants of the Windows malware have been equipped with the ability to communicate over a P2P network, thereby allowing it to bypass traditional command-and-control server shutdown tactics.
    confidence_band: high
references:
  - https://thehackernews.com/2026/09/authorities-turn-salitys-p2p-network.html
iocs:
  - type: ip
    value: 188.166.101.148
ioc_counts:
  ip: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Block sinkhole IP 188.166.101.148 and monitor for traffic to this address as a sign of infection.
      owner: SOC
      due: 24h
      evidence: Source explicitly identifies this address as the beacon destination for infected hosts.
  mitigation_plan:
    - priority: immediate
      action: Identify infected hosts via firewall/proxy logs and perform full system remediation or re-imaging.
      owner: IT Operations
      addresses: Sality Botnet
      evidence: Disruption prevents new payloads, but existing malware remains active.
---

The U.S. Department of Justice, in coordination with authorities from Bulgaria, Hungary, and Romania, along with CrowdStrike and the Shadowserver Foundation, executed a coordinated takedown of the Sality P2P botnet on August 31, 2026. Active since 2003, Sality functioned as a resilient, self-propagating file infector capable of modifying Windows executables. The botnet utilized two independent P2P network versions to facilitate malicious activities including credential theft, spam distribution, DDoS attacks, and the delivery of the EggJagger cryptocurrency clipper.

The disruption was achieved by exploiting the P2P protocol's lack of authentication and cryptographic identity. By performing peer list manipulation, authorities inserted sinkhole entries into the peer lists of super-peers, effectively isolating infected machines from the threat actor's command-and-control infrastructure. While this prevents new payload downloads, existing infections on local systems remain active and require remediation. The operation highlights the vulnerability of P2P architectures when they rely on trust-based peer verification without cryptographic signing.

## Attack Chain

1. Initial infection occurs via malicious file propagation through network shares, removable USB media, or peer-to-peer file sharing.
2. The malware executes and performs local file infection by appending malicious code to existing Windows executables on the disk.
3. The infected host initializes a P2P handshake to join the Sality botnet, blindly trusting other reachable peers provided by the network.
4. The botnet establishes persistence through self-replication, ensuring it can survive standard C2 server takedowns by utilizing a decentralized peer list.
5. The bot receives command-and-control instructions via the P2P network to download secondary payloads, such as the EggJagger clipper.
6. The EggJagger payload monitors system clipboard data to intercept cryptocurrency wallet addresses and perform unauthorized transaction redirection.
7. The botnet may be repurposed for distributed denial-of-service (DDoS) attacks against targeted financial or political entities.
8. Final objective is achieved through persistent financial theft or disruption of services via DDoS.

## Impact

Sality has maintained a global footprint for over two decades, impacting more than 15,000 machines. Observed damage includes the theft of at least $150,000 via cryptocurrency clipjacking and the execution of politically and financially motivated DDoS attacks against international forums and financial organizations. The botnet's ability to infect industrial PLCs further complicates the threat profile by potentially endangering critical infrastructure operations.

## Recommendation

Prioritize the identification and remediation of compromised assets using network and endpoint telemetry.

* Enable network monitoring to detect outbound UDP traffic to the sinkhole IP address 188.166.101.148; this indicates a system is still infected.
* Block all URLs listed in the IOC table at the organizational proxy or DNS resolver to prevent further secondary payload retrieval.
* Perform host-level scans for modified Windows executables, as Sality persists by attaching itself to legitimate files on the disk.
* Enforce security policies to disable or restrict the use of unauthorized removable media and peer-to-peer file sharing software in enterprise environments.
