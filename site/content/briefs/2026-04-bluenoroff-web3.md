---
title: BlueNoroff Targeting Web3 Sector via Spear Phishing
slug: 2026-04-bluenoroff-web3
description: BlueNoroff, a subgroup of the Lazarus Group, is targeting North American Web3 companies through spear-phishing campaigns, impersonating Fintech legal professionals.
date: "2026-04-27T12:00:56Z"
severities:
  - high
actors:
  - BlueNoroff
tags:
  - bluenoroff
  - spear-phishing
  - web3
  - cryptocurrency
  - fintech
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
rules:
  - title: Detect PowerShell Download Cradle
    description: Detects PowerShell executing a download cradle, which downloads and executes code from a remote URL.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.001
      - T1190
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious PowerShell Encoded Command
    description: Detects PowerShell execution with encoded command option, a common technique for obfuscating malicious code.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Arctic Wolf identified a targeted intrusion campaign against a North American Web3/cryptocurrency company, attributing it to BlueNoroff, a financially motivated subgroup of the Lazarus Group. The attackers impersonated a reputable figure in the Fintech legal space to conduct spear-phishing. This campaign highlights the group's continued interest in cryptocurrency-related targets and their evolving social engineering tactics. The use of impersonation tactics suggests a high level of…
