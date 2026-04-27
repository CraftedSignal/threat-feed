---
title: Axios npm Package Compromised via Social Engineering
slug: 2026-04-axios-npm-hack
description: North Korean threat actors (UNC1069) compromised the Axios npm package by socially engineering a maintainer with a fake Microsoft Teams update delivering a RAT, leading to the injection of a malicious dependency and a supply chain attack.
date: "2026-04-04T20:30:42Z"
severities:
  - critical
actors:
  - UNC1069
tags:
  - supply chain attack
  - npm
  - social engineering
  - rat
  - unc1069
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1496
    technique_name: Resource Hijacking
  - tactic_id: TA0009
    tactic_name: Supply Chain Compromise
    technique_id: T1199
    technique_name: Trusted Relationship
references:
  - https://www.bleepingcomputer.com/news/security/axios-npm-hack-used-fake-teams-error-fix-to-hijack-maintainer-account/
rules:
  - title: Detect Suspicious NPM Package Installation
    description: Detects npm package installations initiated by unusual parent processes, which may indicate a supply chain attack or compromised developer environment.
    platform: sigma
    severity: medium
    tactics:
      - supply_chain
    techniques:
      - T1199
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious plain-crypto-js Dependency
    description: Detects the installation or use of the plain-crypto-js dependency.
    platform: sigma
    severity: high
    tactics:
      - supply_chain
    techniques:
      - T1199
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On April 4, 2026, the maintainers of the Axios HTTP client disclosed a social engineering attack targeting one of their developers. The attack, attributed to the North Korean threat actor UNC1069, involved impersonating a legitimate company to build trust with the targeted developer. The attacker used a fake Microsoft Teams update disguised as a critical error fix to deploy a remote access trojan (RAT). This RAT allowed the attackers to gain access to the developer's system and npm credentials…
