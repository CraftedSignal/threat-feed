---
title: China-Aligned FamousSparrow Deploys SparroWocky Backdoor in Latin America
slug: 2026-09-famoussparrow-sparrowocky
description: The state-sponsored threat actor FamousSparrow is deploying the new modular SparroWocky C++ backdoor against government entities in Latin America using advanced anti-analysis techniques.
date: "2026-09-17T14:09:24Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Salt Typhoon
  - GhostEmperor
  - FamousSparrow
  - UNC5807
tags:
  - cyber-espionage
  - backdoor
  - windows
  - latam
  - state-sponsored
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: As observed in the case of SparrowDoor, the malware is triggered by means of a DLL sideloading chain.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Mbed TLS, to establish a secure communication channel with its command-and-control (C2) server
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
    evidence: It can also collect general information about the compromised machine and the IP addresses of its network interfaces
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1113
    technique_name: Screen Capture
    evidence: take periodic screenshots
    confidence_band: high
references:
  - https://thehackernews.com/2026/09/china-aligned-famoussparrow-deploys.html
iocs:
  - type: ip
    value: 216.238.110.120
ioc_counts:
  ip: 1
rules:
  - title: Detect DLL Sideloading via Suspicious Image Load
    description: Detects potential DLL sideloading where a known legitimate process loads a DLL from a suspicious directory
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1574.002
    data_sources:
      - image_load
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Block 216.238.110.120 at egress firewalls
      owner: SOC
      due: 24h
      evidence: Identified as C2 infrastructure in brief
  hunt_leads:
    - lead: Search for unsigned DLLs loaded by signed executables in non-standard directories
      technique_id: T1574.002
      data_needed:
        - Sysmon Event ID 7
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Sideloading chain utilized by malware
---

The China-aligned state-sponsored threat actor FamousSparrow has introduced a new modular C++ backdoor, SparroWocky, targeting government entities in Latin America. Since at least August 2025, the group has shifted away from its legacy SparrowDoor implant to this sophisticated successor. SparroWocky demonstrates advanced engineering, integrating open-source libraries such as Mbed TLS for encrypted command-and-control (C2) communication, MinHook for thread obfuscation, and a COFF loader for executing in-memory plugins. The malware employs complex anti-analysis tactics, including call stack spoofing via a variant of SilentMoonwalk to evade security product monitoring. FamousSparrow focuses on cyber espionage, with telemetry indicating that 90% of observed targeting occurs within Latin American nations, specifically Argentina, Ecuador, Guatemala, Honduras, Panama, Peru, Puerto Rico, and Venezuela. The group's ability to integrate custom and open-source tooling directly into its primary implant indicates a high level of operational maturity and a persistent threat to regional governmental infrastructure.

## Attack Chain

1. Initial access is achieved via unknown vectors, though subsequent stages rely on a consistent DLL sideloading chain.
2. A legitimate, signed executable is launched, which serves as a host to load a malicious loader DLL.
3. The loader DLL decrypts and executes the main SparroWocky payload in memory.
4. The backdoor initiates secure C2 communication with the server at 216.238.110.120 using Mbed TLS.
5. The malware employs MinHook to obfuscate thread start addresses and uses SilentMoonwalk for call stack spoofing to defeat behavioral analysis.
6. SparroWocky utilizes a COFF Loader to dynamically inject and execute additional plugins for expanded capabilities.
7. The actor performs data collection, including network interface discovery (T1016), file operations, and periodic screen captures (T1113).
8. Final objectives include file exfiltration and eventual self-deletion of the backdoor from the host system.

## Impact

Successful deployment of SparroWocky results in long-term persistent access for cyber espionage activities against governmental entities. The malware provides the actor with full control over compromised systems, including the ability to exfiltrate sensitive documents, conduct real-time surveillance via screenshots, and pivot through networks using TCP proxying. The widespread targeting across eight Latin American countries suggests a coordinated intelligence gathering campaign.

## Recommendation

Prioritize monitoring of network traffic to identified C2 infrastructure and endpoint activity related to suspicious DLL loading.
* Block the C2 IP address 216.238.110.120 at the perimeter firewall and DNS resolver.
* Deploy Sigma rules to detect suspicious DLL sideloading patterns where signed binaries load non-standard DLLs from application directories.
* Hunt for in-memory execution patterns associated with COFF loaders and the use of the MinHook library within legitimate process memory spaces.
* Investigate endpoints for unexpected C2 traffic patterns consistent with Mbed TLS, particularly from processes that do not typically initiate network connections.
