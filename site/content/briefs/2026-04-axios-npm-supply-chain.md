---
title: Axios NPM Supply Chain Attack Delivering Platform-Specific RATs
slug: 2026-04-axios-npm-supply-chain
description: A supply chain attack on the Axios NPM package injected malicious code into versions v1.14.1 and v0.30.4, leading to the deployment of platform-specific remote access trojans (RATs) after the installation of a rogue dependency that communicated with attacker-controlled infrastructure to retrieve malicious payloads for Windows, MacOS, and Linux.
date: "2026-04-04T12:00:00Z"
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

On March 31, 2026, the official Axios node package manager (npm) package was compromised in a supply chain attack. The attack resulted in the deployment of two malicious versions, v1.14.1 and v0.30.4. Axios is a widely-used JavaScript library for making HTTP requests, with approximately 100 million downloads per week. The malicious packages were available for around three hours. The compromised packages introduced a fake runtime dependency, 'plain-crypto-js', that executes automatically after…
