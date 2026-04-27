---
title: EmEditor Supply Chain Compromise Delivering Infostealer
slug: 2026-03-emeditor-supply-chain
description: A trojanized EmEditor installer was distributed through a trusted source, delivering an infostealer, highlighting how attackers exploit legitimate software distribution channels to bypass user trust and security controls.
date: "2026-03-19T00:00:00Z"
severities:
  - high
tags:
  - supply-chain
  - infostealer
  - windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
references:
  - https://www.reddit.com/r/blueteamsec/comments/1rxdurz/emeditor_supply_chain_analysis_why_publisher/
  - https://techcommunity.microsoft.com/blog/microsoftsecurityexperts/when-trust-becomes-the-attack-vector-analysis-of-the-emeditor-supply-chain-compr/4499552
rules:
  - title: Detect Suspicious Installer Execution
    description: Detects potential malicious installers executing from temporary directories.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - process_creation
      - windows
  - title: Detect Infostealer Process Creation
    description: Detects processes associated with common info-stealing malware, based on command line and process name.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A supply chain compromise involving the EmEditor text editor led to the distribution of a trojanized installer. Attackers replaced the legitimate EmEditor installer with a malicious version containing an infostealer. This compromised installer was then distributed through trusted or official channels, deceiving users into installing the malware. This incident underscores the importance of verifying software integrity, even when obtained from seemingly reputable sources, and highlights the…
