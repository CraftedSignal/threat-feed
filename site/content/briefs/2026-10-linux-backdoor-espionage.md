---
title: Linux Backdoors Targeting Telecom and Network Appliances in Asia
slug: 2026-10-linux-backdoor-espionage
description: Threat actors, linked to Red Menshen, are deploying advanced Linux backdoors like BPFDoor and AVERAT against telecom and network appliances in South Korea and Taiwan, utilizing process name spoofing and BPF-based triggers to evade detection.
date: "2026-10-06T21:05:30Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Red Menshen
tags:
  - espionage
  - linux
  - malware
  - telecom
  - network-security
  - red-menshen
vendors:
  - Jiran Group
  - ShareTech
products:
  - SpamSniper
  - ShareTech appliances
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: Each component adopts names and conventions designed to look unremarkable in the environment it targets.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: AVERAT, a modular implant that uses the Simple Mail Transfer Protocol (SMTP) for command-and-control (C2).
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1205
    technique_name: Traffic Signaling
    evidence: BPFdoor abuses the Berkeley Packet Filter (BPF) functionality to inspect incoming network traffic.
    confidence_band: high
references:
  - https://thehackernews.com/2026/10/linux-backdoors-impersonate-email.html
iocs:
  - type: domain
    value: mx.zxopfds.com
ioc_counts:
  domain: 1
rules:
  - title: Detect AVERAT C2 Beaconing Activity
    description: Detects outbound TCP connections on port 25 from unexpected processes or hosts indicative of AVERAT C2 communication
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.003
    data_sources:
      - network_connection
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block mx.zxopfds.com at DNS resolver
      owner: SOC
      due: 4h
      evidence: Verified as AVERAT C2 infrastructure
  hunt_leads:
    - lead: Identify processes with names like udevds, ora_ppmond, or spam related names in non-standard paths
      technique_id: T1036
      data_needed:
        - Process tree logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Threat actors name their malicious software after legitimate system processes.
---

Threat actors linked to the group known as Red Menshen are conducting sophisticated cyber espionage campaigns targeting telecom providers and edge network appliances in South Korea and Taiwan. The campaign involves the deployment of specialized Linux backdoors, including new variants of BPFDoor, BPF Rekoobe, and a previously unreported modular implant dubbed AVERAT. These implants are specifically designed for high-privilege environments, using regionalized disguise tactics to blend into the target environment. They achieve this by impersonating legitimate local security software, such as the SpamSniper email security solution or Oracle database background processes, and by leveraging kernel-level packet inspection to listen for trigger packets. The attackers have demonstrated agility, refining their C2 mechanisms to move from simple BPF magic packets to HTTPS POST request wrapping and SMTP-based beaconing to bypass standard deep packet inspection and network security controls common in telecom infrastructures.

## Attack Chain

1. Initial access is achieved against edge appliances, likely through exploitation of undisclosed vulnerabilities or credential abuse in regional telecom environments.
2. The installer drops an ELF binary into the target directory, such as the ShareTech "/addpkg/sbin/" path.
3. The dropper derives an encryption key from a hardcoded string (e.g., "ShareTech") to decrypt a hidden shell script.
4. The decrypted script executes two malicious components: a local installer ("ntpdate") and the core payload ("udevds" / AVERAT).
5. The dropper implements defense evasion by deleting itself and the intermediate script after a 10-second window to minimize footprint.
6. The backdoor establishes periodic polling (600-699 seconds) to a C2 server via TCP port 25, leveraging SMTP traffic to mask C2 communications.
7. Upon receipt of commands, the malware performs interactive shell tasks, exfiltration, or proxying through the appliance.
8. The final objective is persistent intelligence collection and data exfiltration from the compromised telecom network node.

## Impact

The campaign targets sensitive telecom and network infrastructure in South Korea and Taiwan, organizations that serve as central communication hubs. Successful compromise grants attackers the ability to monitor traffic, exfiltrate subscriber data, and maintain long-term persistence on edge appliances. This activity demonstrates a focused effort to gain intelligence by compromising trusted security products (SEGs) within enterprise networks, mirroring previous campaigns against Barracuda ESG appliances.

## Recommendation

Prioritized actions for detection engineering and security operations:
- Audit all Linux systems for unauthorized or suspicious raw packet sockets and BPF filters that do not align with authorized network monitoring tools.
- Implement network egress filtering to restrict and monitor outbound traffic on TCP port 25 originating from non-mail service processes.
- Deploy file integrity monitoring (FIM) or process execution logging to detect the creation or execution of binaries posing as system daemons (e.g., "udevds", "ora_ppmond").
- Review the list of loaded shared object (*.so) modules to identify unauthorized extensions loaded by AVERAT (code 1010).
- Block the domain 'mx.zxopfds.com' at the enterprise DNS resolver and egress proxy as it is confirmed C2 infrastructure.
