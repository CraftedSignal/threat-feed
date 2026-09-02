---
title: Disruption of the Sality Peer-to-Peer Botnet
slug: 2026-09-sality-disruption
description: CrowdStrike and international law enforcement neutralized the long-running Sality P2P botnet, which leveraged polymorphic file infection and decentralized C2 to distribute malicious payloads to over 15,000 infected machines.
date: "2026-09-02T11:59:42Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - SALTY SPIDER
tags:
  - botnet
  - p2p
  - malware
  - file-infection
  - counter-adversary-operations
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1571
    technique_name: Non-Standard Port
    evidence: Sality's P2P architecture had no single point of failure.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
    evidence: The botnet enabled the operator to distribute malicious payloads to over 15,000 infected machines worldwide.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/inside-sality-botnet-disruption-operation/
iocs:
  - type: url
    value: http://theunforgiven.p8.hu/img/top.gif
  - type: url
    value: http://painelwebradiodigital.awardspace.info/v3/readme.pdf
  - type: url
    value: http://sgwebdesigner.free.fr/left.gif
  - type: url
    value: http://www.yonelco.com/icon.png
  - type: url
    value: http://pozdravizbeograda.com/readme.pdf
  - type: url
    value: http://highclass.atspace.com/styles.gif
  - type: url
    value: http://situluimihai.3x.ro/top.png
  - type: url
    value: http://gatheredovertime.com/nb4
  - type: url
    value: http://imagebucket.biz/nv4
ioc_counts:
  url: 9
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block identified malicious URL patterns at proxy and DNS layers.
      owner: SOC
      due: 24h
      evidence: Source contains list of malicious URL packs.
  hunt_leads:
    - lead: Scan endpoints for Sality memory signatures using provided YARA rules.
      technique_id: T1055
      data_needed:
        - Memory scanning telemetry
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Sality v3/v4 memory signatures provided in source.
---

On August 31, 2026, CrowdStrike's Counter Adversary Operations team, in coordination with the FBI, DOJ, DCIS, and international law enforcement agencies, executed a successful sinkholing operation against the Sality P2P botnet. Active since 2003, Sality functioned as a highly resilient, polymorphic file-infecting malware that operated without centralized command-and-control infrastructure. By leveraging a decentralized peer-to-peer architecture, infected hosts communicated directly with one another to receive tasking and updates. The botnet utilized two distinct, incompatible protocol versions (v3 and v4) that shared a common codebase but used unique cryptographic keys. The operation successfully isolated infected machines by subverting the P2P communication channel, rendering the botnet infrastructure inert and cutting off access for approximately 15,000 active nodes globally.

## Attack Chain

1. Initial infection typically occurs via polymorphic file infection of local executable files or propagation through unprotected network shares.
2. Malware establishes persistence on the host, often injecting code into legitimate processes to evade detection.
3. The infected host performs a peer discovery process to identify other active Sality nodes in the P2P network.
4. The host attempts to reach out to pre-configured URL packs to download malicious updates, configuration changes, or secondary payloads.
5. The botnet client verifies payload signatures using hardcoded RSA public keys embedded within the malware binary.
6. The malware executes functional modules (e.g., clipjacking for credential or cryptocurrency theft, proxying, or DDoS tasking).
7. The compromised host continues to spread the infection to other systems via network shares or removable media until isolated by security controls.

## Impact

Sality operated for over two decades, infecting thousands of systems worldwide and maintaining a robust infrastructure capable of delivering various malicious payloads. The botnet's capabilities included credential theft, cryptocurrency transaction hijacking, and DDoS participation. The disruption rendered these capabilities inert for 15,000 active infections at the time of the operation.

## Recommendation

1. Deploy the YARA rules provided in this brief to scan memory on enterprise endpoints for active Sality v3 and v4 infections.
2. Block outbound traffic to the known malicious URL packs associated with Sality v3 and v4 at the network perimeter.
3. Scan internal network shares for infected executables that may attempt to re-propagate the Sality file-infector.
4. Review endpoint logs for unexpected execution of processes that attempt to verify signatures using the known RSA public keys embedded in Sality binaries.
