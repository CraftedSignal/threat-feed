---
title: MovieReaper Multi-Stage Trojan Campaign
slug: 2026-09-moviereaper-trojan
description: MovieReaper is a multi-stage modular Trojan distributed via compromised torrent files on itorrents.org that leverages the Solana blockchain for C2 discovery and achieves persistence via UAC bypass.
date: "2026-09-17T13:13:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - trojan
  - modular
  - blockchain
  - torrent
  - windows
  - malware
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204.002
    technique_name: 'User Execution: Malicious File'
    evidence: The campaign began with the mass infection of users via compromised torrent tracker file storage.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder'
    evidence: Stage 3 performs UAC Bypass and achieves persistence using public techniques.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1568.002
    technique_name: 'Dynamic Resolution: Domain Generation Algorithms'
    evidence: The second stage performs an HTTPS request to the Solana blockchain... to fetch the base64-encoded address of a second C2.
    confidence_band: high
references:
  - https://securelist.com/moviereaper-malware-torrent-odyssey-solana/121344/
iocs:
  - type: domain
    value: deadhub.org
  - type: ip
    value: 193.23.118.155
  - type: hash_md5
    value: A0B13781EDD7CFDAB13D79AFFF3C83C1
  - type: domain
    value: itorrents.org
ioc_counts:
  domain: 2
  hash_md5: 1
  ip: 1
rules:
  - title: Detect MovieReaper Persistence in Telemetry Directory
    description: Detects processes attempting to run from the Microsoft Telemetry folder, a known persistence location for MovieReaper
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
  immediate_actions:
    - action: Block C2 infrastructure and monitor for processes in the Telemetry folder
      owner: SOC
      due: 24h
  hunt_leads:
    - lead: Search for files in C:\ProgramData\Microsoft\Windows\Telemetry\ that are not standard Microsoft binaries
      technique_id: T1547.001
      priority: high
      confidence: high
      disposition: hunt_now
  mitigation_plan:
    - priority: immediate
      action: Block C2 domains and IPs at perimeter firewalls and DNS proxies
      owner: Network Security
---

MovieReaper is a sophisticated multi-stage modular Trojan framework identified in August 2026. The campaign primarily spreads by abusing the itorrents.org repository, which serves malicious torrent files disguised as popular media, such as the film "The Odyssey." The malware is designed to evade sandbox analysis through manual PEB-based library resolution and syscall-driven shellcode execution. Notably, the framework uses the Solana blockchain to dynamically resolve secondary C2 infrastructure, enhancing resilience against takedown efforts. Once deployed, the malware performs UAC bypasses and establishes persistence by masquerading as Microsoft telemetry components in the C:\ProgramData\Microsoft\Windows\Telemetry\ directory. The modular architecture allows the threat actors to deploy additional capabilities via COFF file injection.

## Attack Chain

1. User downloads a malicious torrent file originating from the compromised itorrents.org repository.
2. Execution of the dropper (e.g., "the odyssey (2026).exe") which uses an anti-debugging mutex (e.g., Global\fnulSktzSqvVLXHU) and manual PEB parsing to locate system functions.
3. Dropper initiates an HTTPS connection to deadhub.org or the fallback 193.23.118.155 to download encrypted shellcode.
4. Execution of the shellcode via NtProtectVirtualMemory and EtwpCreateEtwThread to map and trigger the second-stage payload.
5. The second-stage implant queries the Solana blockchain account 6pnDGAiHgyPdmckM5Qt1YbanGzrX43WLEU159nRaNLDm to retrieve the address of the secondary C2 server.
6. The secondary C2 provides a COFF module that performs a UAC bypass and persistence setup.
7. The process copies itself to C:\ProgramData\Microsoft\Windows\Telemetry\msedge.exe and restarts to facilitate further module downloads.

## Impact

The campaign has infected hundreds of victims, including both individuals and organizations, across diverse regions such as Russia, Türkiye, Japan, Kenya, Uganda, Colombia, and several European nations. Successful execution allows for remote command execution, potential data exfiltration, and long-term persistent access to the victim's environment.

## Recommendation

* Monitor for execution of binaries masquerading as Microsoft telemetry components under C:\ProgramData\Microsoft\Windows\Telemetry\.
* Block and investigate DNS queries for deadhub.org and network connections to 193.23.118.155.
* Implement detection for unusual mutex patterns generated by process loaders, such as random strings containing high-entropy characters.
* Deploy Sigma rules to detect unauthorized execution of binaries from non-standard ProgramData subdirectories.
* Train users to avoid downloading pirated media and to be skeptical of installation guides that request disabling antivirus software.
