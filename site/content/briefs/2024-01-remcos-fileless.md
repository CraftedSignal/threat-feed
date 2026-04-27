---
title: Fileless Multi-Stage Remcos RAT via Phishing
slug: 2024-01-remcos-fileless
description: A fileless multi-stage Remcos RAT is delivered via phishing, achieving memory-resident execution, but specific technical details are not provided in this brief.
date: "2026-03-15T15:34:12Z"
severities:
  - high
tags:
  - remcos
  - rat
  - fileless
  - phishing
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1055
    technique_name: Process Injection
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Remote File Download
references:
  - https://www.reddit.com/r/blueteamsec/comments/1ruh3nu/fileless_multistage_remcos_rat_from_phishing_to/
  - https://www.trellix.com/blogs/research/fileless-multi-stage-remcos-rat-phishing-to-memory/
rules:
  - title: Suspicious Process Injection by PowerShell
    description: Detects PowerShell injecting code into another process, a technique often used in fileless attacks.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1055.001
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: PowerShell Download and Execute via WebClient
    description: Detects PowerShell downloading and executing code directly from the internet, common in fileless attacks.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1105
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat brief discusses a Remcos RAT infection chain that utilizes a fileless, multi-stage approach. While specific details regarding the initial phishing lure, exploitation method, and Remcos RAT version are absent from the original report, the core focus is on the fileless execution and memory residency of the RAT. The attack begins with an unspecified phishing attack and culminates in a Remcos RAT running entirely in memory, hindering traditional disk-based forensic analysis. This type…
