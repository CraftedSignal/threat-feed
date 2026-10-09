---
title: Evolution of UAC-0099's MATCHBOIL Downloader
slug: 2026-10-matchboil
description: UAC-0099, a Russia-aligned threat actor, uses the evolving MATCHBOIL C# downloader to target Ukrainian sectors via spearphishing and secondary payload delivery.
date: "2026-10-09T07:56:08Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - UAC-0099
tags:
  - malware
  - downloader
  - csharp
  - uac-0099
  - ukraine
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The malware is distributed via malicious links in spearphishing emails.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: MATCHBOIL has persisted its payload via a Windows registry Run entry.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: The analyzed MATCHBOIL versions show a change in code obfuscation from originally using Unicode symbol renaming to now employing the Eziriz .NET Reactor obfuscator.
    confidence_band: high
references:
  - https://www.welivesecurity.com/en/eset-research/matchboil-new-tricks-same-old-evil-intentions/
iocs:
  - type: domain
    value: virtualdailyplanner.pro
  - type: domain
    value: telemetry-conf.com
  - type: ip
    value: 64.95.10.223
  - type: ip
    value: 64.95.13.210
ioc_counts:
  domain: 2
  ip: 2
rules:
  - title: Detect MATCHBOIL Persistence via Registry Run Key
    description: Detects potential MATCHBOIL persistence mechanisms via modifications to the Windows Registry Run key.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block the identified C2 domains and IPs in firewall and DNS egress policies.
      owner: SOC
      due: 24h
      evidence: IOC list provided in the brief.
  hunt_leads:
    - lead: Search for VBScript files executed from temporary directories or user profiles.
      technique_id: T1059.005
      data_needed:
        - Process creation logs showing script execution
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Malware distribution via VBScript payload.
---

UAC-0099, a Russia-aligned cyberespionage group active since at least 2022, has been systematically evolving the MATCHBOIL downloader since April 2024. MATCHBOIL is a custom C# malware designed to download, install, and persist subsequent payloads, such as the MATCHWOK backdoor. Initially a straightforward one-shot downloader, the malware has matured to include sophisticated obfuscation via the Eziriz .NET Reactor, multi-stage execution on timers, and sandbox evasion techniques. ESET researchers have identified victims across various Ukrainian sectors, including transportation, manufacturing, and energy. The actor frequently acts as an initial access broker for other groups, including Sandworm. Defenders should monitor for suspicious C# binaries, unusual VBScript execution, and irregular HTTPS traffic patterns associated with identified C2 domains.

## Attack Chain

1. The attacker sends spearphishing emails containing links to an archive file.
2. The victim downloads and manually executes a VBScript payload contained within the archive.
3. The VBScript downloads and executes the MATCHBOIL downloader binary.
4. MATCHBOIL performs environment checks, including WMI queries and sandbox detection, to verify the execution environment.
5. MATCHBOIL initiates an HTTPS connection to the C2 server to retrieve a command identifier in an HTTP header.
6. A second HTTPS request fetches an HTML-formatted response, from which the malware extracts a hex-encoded secondary payload using regular expressions.
7. The extracted binary is decoded and installed into a directory within %LOCALAPPDATA%.
8. Persistence is established via scheduled tasks or Windows Registry Run keys to execute the installed payload.

## Impact

UAC-0099 targets Ukrainian governmental, financial, and media organizations. Successful compromise leads to the installation of backdoors like MATCHWOK, enabling unauthorized remote access, data exfiltration, and potential facilitation of further malicious operations by related threat groups such as Sandworm.

## Recommendation

* Monitor endpoint telemetry for VBScript processes spawning child processes or network connections, which may indicate the initiation of the MATCHBOIL infection chain.
* Implement Sigma rules to detect suspicious WMI query patterns (e.g., CPUID, BIOS serial number retrieval) and unexpected registry modifications in the 'Run' key.
* Block and monitor traffic to the C2 domains provided in the IOC table at the network perimeter.
* Deploy detections for the execution of .NET-based binaries that exhibit code obfuscation or rely on non-standard HTTP header structures for C2 communication.
