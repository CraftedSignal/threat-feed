---
title: Lotus Data Wiper Targeting Venezuelan Energy and Utility Firms
slug: 2026-04-lotus-wiper
description: The Lotus wiper, a previously undocumented data-wiping malware, was deployed against Venezuelan energy and utilities organizations in 2025, overwriting physical drives, deleting files, and rendering systems unrecoverable.
date: "2026-04-22T12:00:00Z"
severities:
  - critical
tags:
  - data-wiper
  - lotus-wiper
  - venezuela
  - energy
  - utilities
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
references:
  - https://www.bleepingcomputer.com/news/security/new-lotus-data-wiper-used-against-venezuelan-energy-utility-firms/
rules:
  - title: Detect UI0Detect Service Modification
    description: Detects changes to the UI0Detect service, potentially indicating preparation for Lotus wiper deployment.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Detect Diskpart Clean All Execution
    description: Detects the execution of diskpart with the 'clean all' command, indicative of disk wiping activities.
    platform: sigma
    severity: critical
    tactics:
      - destruction
    techniques:
      - T1490
    data_sources:
      - process_creation
      - windows
  - title: Detect suspicious Robocopy usage for data overwriting
    description: Detects Robocopy being used to overwrite directory contents, a technique used by the Lotus wiper.
    platform: sigma
    severity: high
    tactics:
      - destruction
    techniques:
      - T1490
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

In 2025, a new data wiper malware known as Lotus was used in targeted attacks against Venezuelan energy and utility companies. The malware, discovered by Kaspersky researchers after being uploaded to a public platform in mid-December 2025 from a Venezuelan machine, aims to completely destroy compromised systems. The attacks coincide with a period of geopolitical tension in the region. The malware not only overwrites data but also removes recovery mechanisms, overwrites the content of physical…
