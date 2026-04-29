---
title: Axios NPM Supply Chain Attack Delivering Platform-Specific RATs
slug: 2026-04-axios-npm-supply-chain
description: A supply chain attack on the Axios NPM package injected malicious code into versions v1.14.1 and v0.30.4, leading to the deployment of platform-specific remote access trojans (RATs) after the installation of a rogue dependency that communicated with attacker-controlled infrastructure to retrieve malicious payloads for Windows, MacOS, and Linux.
date: "2026-04-04T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - supply-chain
  - npm
  - javascript
  - rat
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Supply Chain Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://blog.talosintelligence.com/axois-npm-supply-chain-incident/
iocs:
  - type: ip
    value: 142.11.206.73
  - type: domain
    value: Sfrclak.com
  - type: hash_sha256
    value: e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09
  - type: hash_sha256
    value: fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf
  - type: hash_sha256
    value: 617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101
  - type: hash_sha256
    value: 92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a
  - type: hash_sha256
    value: ed8560c1ac7ceb6983ba995124d5917dc1a00288912387a6389296637d5f815c
ioc_counts:
  domain: 1
  hash_sha256: 5
  ip: 1
rules:
  - title: Detect Suspicious Process Connecting to Known Malicious IP
    description: Detects processes establishing network connections to the actor-controlled IP address.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Suspicious PowerShell Execution from ProgramData
    description: Detects powershell execution from the ProgramData directory, indicating potential execution of the downloaded ps1 script.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On March 31, 2026, the official Axios node package manager (npm) package was compromised in a supply chain attack. The attack resulted in the deployment of two malicious versions, v1.14.1 and v0.30.4. Axios is a widely-used JavaScript library for making HTTP requests, with approximately 100 million downloads per week. The malicious packages were available for around three hours. The compromised packages introduced a fake runtime dependency, 'plain-crypto-js', that executes automatically after installation. This dependency then communicates with attacker-controlled infrastructure at 142.11.206.73, pulling down platform-specific payloads for Linux, MacOS, and Windows. The payloads are remote access trojans (RATs), enabling the attackers to gather information and execute additional malicious activities.

## Attack Chain

1.  The attacker compromised the Axios NPM package and injected malicious code.
2.  Malicious versions v1.14.1 and v0.30.4 were published to the NPM registry.
3.  The malicious packages introduce a fake runtime dependency named 'plain-crypto-js'.
4.  Upon installation of the compromised package, the 'plain-crypto-js' dependency executes automatically via a post-install script.
5.  The dependency connects to the attacker-controlled IP address 142.11.206.73 to retrieve a platform-specific payload.
6.  On MacOS, a binary named "com.apple.act.mond" is downloaded and executed using zsh.
7.  On Windows, a PowerShell script (6202033.ps1) is downloaded, and the legitimate powershell.exe is copied to "%PROGRAM DATA%\wt.exe", and the ps1 script is executed with hidden and execution policy bypass flags.
8.  On Linux, a Python backdoor is downloaded and executed. The downloaded executables act as Remote Access Trojans (RATs) exfiltrating credentials and enabling remote management.

## Impact

This supply chain attack could lead to significant compromise across numerous organizations using the Axios library. The actors exfiltrate credentials and gain remote management capabilities. All credentials present on systems that installed the malicious package should be considered compromised and immediately rotated. The widespread use of Axios means the impact could extend to many applications and systems, potentially enabling further attacks leveraging compromised credentials. Supply chain attacks like these affecting widely used libraries, as seen in 25% of the top 100 vulnerabilities in the Cisco Talos 2025 Year in Review, highlight the substantial risk they pose.

## Recommendation

*   Roll back to safe Axios versions (v1.14.0 or v0.30.3) immediately to prevent further compromise, as mentioned in the overview.
*   Investigate systems that downloaded malicious packages (v1.14.1 or v0.30.4) for signs of follow-on payloads from the actor-controlled infrastructure, as described in the overview.
*   Block the actor-controlled IP address 142.11.206.73 and domain Sfrclak.com at the network perimeter to prevent further communication with the malicious infrastructure, per the IOC list.
*   Monitor for execution of PowerShell scripts from unusual locations, specifically "%PROGRAM DATA%\wt.exe", as part of the attack chain.
*   Implement a process creation rule to alert when processes connect to external IPs using uncommon parent processes. See example rule below.
