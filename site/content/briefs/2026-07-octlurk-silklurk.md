---
title: OctLurk and SilkLurk Memory-Resident Backdoors Targeting Central Asia
slug: 2026-07-octlurk-silklurk
description: OctLurk and SilkLurk are sophisticated, memory-resident backdoors targeting government and research entities in Central Asia since January 2025, utilizing machine-specific key derivation for payload decryption and modular plugin injection.
date: "2026-07-30T13:38:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - backdoor
  - cyber-espionage
  - memory-resident
  - central-asia
  - chinese-speaking
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543.003
    technique_name: Windows Service
    evidence: The 1.bat script creates a service named NgcCIntSvc, which loads the loader DLL named oleasapi.dll.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053.005
    technique_name: Scheduled Task
    evidence: The attacker created a scheduled task named GoogleUpDate on remote machines using admin credentials.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1055.001
    technique_name: Dynamic-link Library Injection
    evidence: The backdoor DLL is reflectively injected into memory and its entry point is executed.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: Web Protocols
    evidence: The backdoor then creates a stream socket using a hard-coded C2 address (dns[.]multitoconference[.]com) and port 443.
    confidence_band: high
references:
  - https://securelist.com/octlurk-silklurk-backdoors-central-asia/120840/
iocs:
  - type: hash_md5
    value: 6ecf84fb18f6747ed08d7598364d853a
  - type: hash_md5
    value: 082d49ef9f14e6811d68c7e0e82e5069
  - type: hash_md5
    value: b874123a80fc4f40e06872b9cb54ebc6
  - type: domain
    value: dns.ssentialserv.xyz
  - type: ip
    value: 154.196.162.76
  - type: domain
    value: dns.multitoconference.com
ioc_counts:
  domain: 2
  hash_md5: 3
  ip: 1
rules:
  - title: Detect Suspicious Service Creation Used by OctLurk
    description: Detects the creation of services identified in the OctLurk campaign
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
---

Since January 2025, government and research organizations across Central Asia - including Afghanistan, Kyrgyzstan, Tajikistan, Uzbekistan, Kazakhstan, and Syria - have been targeted by two sophisticated, memory-resident backdoors: OctLurk and SilkLurk. These tools, likely operated by a Chinese-speaking threat actor, utilize custom loaders that generate decryption keys derived from victim-specific hardware information, such as the C: drive serial number, to perform reflective DLL injection.

The attackers deploy these backdoors by creating malicious Windows services or scheduled tasks (e.g., 'GoogleUpDate') that execute obfuscated batch scripts. Once the backdoor is injected, it communicates with C2 infrastructure via port 443 using a complex, multi-stage XOR and zlib-compression scheme. The malware is highly modular, allowing the operators to download and inject memory-only plugins for command shell execution, filesystem management, keystroke and mouse event synthesis, credential dumping, and keylogging. The campaign also involves 'LurkProxy', a utility with similar architecture used to facilitate network operations.

## Attack Chain

1. Attacker establishes persistence by creating a scheduled task (e.g., 'GoogleUpDate') or a custom service (e.g., 'NgcCIntSvc', 'Cusrxsrv') on the victim machine using compromised admin credentials.
2. The persistence mechanism executes a local batch script (e.g., '1.bat' or 'auto.bat') which installs a loader DLL (e.g., 'oleasapi.dll' or 'msbasesysdc.dll') into the system.
3. The service registry is configured to call the 'RegisterService' export of the loader DLL upon service startup.
4. The loader DLL performs multi-stage decryption of the payload path using a hard-coded key and a key derived from the victim's hardware (e.g., drive serial number).
5. The loader retrieves and decrypts the backdoor DLL, then injects it into memory using reflective DLL injection techniques.
6. The backdoor contacts the C2 server (e.g., 'dns.multitoconference.com') over port 443, transmitting victim system information encrypted with hard-coded XOR keys and zlib compression.
7. The backdoor receives and loads modular plugins directly into memory to perform post-exploitation activities, including credential dumping, keylogging, and file exfiltration.

## Impact

This campaign has successfully compromised government agencies, foreign affairs ministries, and law enforcement entities across Central Asia. If the attack succeeds, the threat actor gains persistent, remote access to sensitive systems, allowing for large-scale data exfiltration, credential theft, and sustained cyber-espionage activities within the targeted sectors.

## Recommendation

1. Deploy the Sigma rules below to monitor for suspicious Windows service creation and scheduled task execution patterns associated with backdoor deployment.
2. Implement strict egress filtering on your network to block connections to known C2 domains: 'dns.multitoconference.com' and 'dns.ssentialserv.xyz'.
3. Monitor for the creation of unauthorized services with suspect names like 'NgcCIntSvc' or 'Cusrxsrv' as documented in the brief.
4. Use Endpoint Detection and Response (EDR) to alert on memory-resident reflective DLL injection attempts targeting system processes.
5. Investigate high-entropy command-line arguments in batch scripts occurring in non-standard directories like 'C:\Users\&lt;username>\Videos\'.
