---
title: Dragon Boss Solutions Adware Disabling Antivirus Protections
slug: 2026-04-dragon-boss-adware
description: Digitally signed adware from Dragon Boss Solutions LLC deploys payloads with SYSTEM privileges to disable antivirus protections on thousands of endpoints across education, utilities, government, and healthcare sectors.
date: "2026-04-16T12:00:00Z"
severities:
  - high
tags:
  - adware
  - antivirus-evasion
  - malware
  - windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
references:
  - https://www.bleepingcomputer.com/news/security/signed-software-abused-to-deploy-antivirus-killing-scripts/
ioc_counts:
  domain: 2
rules:
  - title: Detect ClockRemoval.ps1 PowerShell Script Execution
    description: Detects the execution of the ClockRemoval.ps1 PowerShell script used to disable antivirus products.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Hosts File Modification Blocking AV Domains
    description: Detects modification of the hosts file to block antivirus vendor domains.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

A digitally signed adware tool distributed by Dragon Boss Solutions LLC has been observed deploying payloads designed to disable antivirus protections. The campaign, discovered by Huntress on March 22, 2026, leverages signed executables initially classified as potentially unwanted programs (PUPs) to gain a foothold on victim machines. These PUPs, often disguised as browser tools like Chromstera Browser, Chromnius, WorldWideWeb, Web Genius, and Artificius Browser, use an advanced update…
