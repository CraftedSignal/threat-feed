---
title: Armored Likho APT Deploys Rust-Based Still Toolkit for Espionage
slug: 2026-08-armored-likho-toolkit
description: The Armored Likho (Eagle Werewolf) threat actor is deploying a new Rust-based cyber-espionage 'Still Toolkit' via a malicious fundraising-themed dropper to exfiltrate Telegram session data and perform covert audio surveillance.
date: "2026-08-13T10:39:43Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Armored Likho
tags:
  - cyber-espionage
  - rust
  - malware
  - telegram
vendors:
  - Telegram
products:
  - Telegram Desktop
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The infection chain starts with an app that mimics a donation service.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: If this parameter is absent, the implant creates a TReload service to keep running in the background.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1125
    technique_name: Audio Capture
    evidence: Still Audio, is an implant for covert audio surveillance.
    confidence_band: high
references:
  - https://securelist.com/armored-likho-still-toolkit/121033/
iocs:
  - type: domain
    value: orderapiserver.info
  - type: domain
    value: tg4service.com
ioc_counts:
  domain: 2
rules:
  - title: Detect Still Sync Persistence via TReload Service
    description: Detects the creation of the TReload service used by Still Sync for persistence
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1543.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
  immediate_actions:
    - action: Block C2 domains orderapiserver.info and tg4service.com
      owner: SOC
      due: 24h
      evidence: Source identifies these as C2 infrastructure.
  hunt_leads:
    - lead: Search for TReload service installation
      technique_id: T1543.003
      data_needed:
        - Process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source specifies this name for persistence.
---

Since May 2026, the Armored Likho (also known as Eagle Werewolf) group has been conducting a targeted cyber-espionage campaign against Russian organizations in the public, IT, and education sectors. The attackers utilize a sophisticated Rust-based dropper built on the Tauri framework, masquerading as a donation service application. Once initialized, this dropper downloads and executes the 'Still Toolkit', a modular espionage suite designed for data exfiltration and persistent surveillance.

The toolkit consists of two primary implants: 'Still Sync', a stealer that targets Telegram session ('tdata') files and leverages the Telegram API for ongoing access to chat logs and media, and 'Still Audio', an implant dedicated to covert audio recording and speech analysis. The malware utilizes gRPC over HTTP/HTTPS with FlatBuffers serialization for command-and-control communication, employing techniques observed in previous campaigns such as machine registration via hardware-based system markers and persistent background services.

## Attack Chain

1. Initial delivery of a Tauri-based dropper application masquerading as a legitimate Russian fundraising service.
2. Execution of the dropper, which displays a deceptive GUI and validates user input before decrypting the secondary payload.
3. The dropper retrieves product catalog data from the C2 domain 'orderapiserver[.]info' to maintain a legitimate appearance.
4. Decryption and execution of the Still Toolkit components (Still Sync and Still Audio) in the background.
5. Still Sync creates a persistent background service named 'TReload' to ensure long-term execution.
6. The implant performs system fingerprinting (CPU ID, BIOS/Motherboard serials) to generate a unique 'sysmarker' and registers the host with the C2 server 'tg4service[.]com'.
7. Still Sync targets the Telegram Desktop 'tdata' directory to extract authentication tokens, enabling unauthorized access to the victim's account via the Telegram API.
8. Still Audio implant initializes covert audio capture, performs local speech detection, and exfiltrates audio streams to the attacker-controlled C2.

## Impact

The campaign facilitates unauthorized access to private corporate and personal Telegram communications, including potentially sensitive media and chat history, alongside real-time audio surveillance of the victim's environment. This poses a significant risk to organizational confidentiality, particularly for entities in the public and IT sectors where internal communications are critical.

## Recommendation

* Block all traffic to the known C2 domains 'orderapiserver[.]info' and 'tg4service[.]com' at the network perimeter.
* Monitor for the creation of non-standard Windows services, specifically looking for the 'TReload' service name using Sysmon Event ID 1.
* Implement endpoint detection rules to identify execution of Tauri-based application installers from untrusted sources or unexpected locations.
* Audit endpoints for the presence of the hidden file 'bin' created by the Still Sync implant in the same directory as the executable.
