---
title: TrueConf Zero-Day Exploitation Leading to Arbitrary Code Execution
slug: 2026-04-trueconf-zero-day
description: Hackers exploited a zero-day vulnerability (CVE-2026-3502) in TrueConf conference servers to execute arbitrary files on connected endpoints, potentially deploying the Havoc C2 framework.
date: "2026-04-02T12:00:00Z"
severities:
  - high
actors:
  - Potentially Chinese-nexus threat actor (TrueChaos)
exploited: true
tags:
  - trueconf
  - zero-day
  - cve-2026-3502
  - supply-chain attack
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
cves:
  - id: CVE-2026-3502
    cvss: 7.8
    epss: 0.02421
references:
  - https://www.bleepingcomputer.com/news/security/hackers-exploit-trueconf-zero-day-to-push-malicious-software-updates/
ioc_counts:
  file_name: 4
rules:
  - title: Suspicious TrueConf Update Execution
    description: Detects suspicious processes executing from the TrueConf update directory, indicating a potential malicious update.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1574.001
    data_sources:
      - process_creation
      - windows
  - title: Potential TrueConf UAC Bypass via iscsicpl.exe
    description: Detects the execution of iscsicpl.exe from a suspicious path, indicating a potential UAC bypass attempt during the TrueChaos campaign.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A threat actor, possibly with Chinese nexus, is exploiting CVE-2026-3502, a zero-day vulnerability in TrueConf versions 8.1.0 through 8.5.2. This vulnerability allows attackers to replace legitimate software updates with malicious variants, leading to arbitrary code execution on connected clients. The attacks, tracked as "TrueChaos" since the beginning of 2026, have targeted government entities in Southeast Asia. TrueConf, a video conferencing platform popular among military forces, government…
