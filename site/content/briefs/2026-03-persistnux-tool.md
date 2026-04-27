---
title: Persistnux - Linux Persistence Detection Tool
slug: 2026-03-persistnux-tool
description: Persistnux is a bash-based tool designed to identify known Linux persistence mechanisms used by attackers to maintain access to compromised systems, generating detailed reports for DFIR analysis.
date: "2026-03-17T12:00:00Z"
severities:
  - medium
tags:
  - persistence
  - linux
  - dfir
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://www.reddit.com/r/cybersecurity/comments/1rvnvmc/persistnux_linux_persistence_tool_hunter/
  - https://github.com/go-LANz/Persistnux
rules:
  - title: Detect Init Script Modification for Persistence
    description: Detects modifications to init scripts, which can be used for persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1543.002
    data_sources:
      - file_event
      - linux
  - title: Detect Cron Job Modification for Persistence
    description: Detects modifications to cron job files, often used for scheduling malicious tasks.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1053.003
    data_sources:
      - file_event
      - linux
  - title: Detect Systemd Service Modification for Persistence
    description: Detects modifications to systemd service files, which can be used for persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1543.004
    data_sources:
      - file_event
      - linux
rules_count: 3
---

Persistnux is a bash-based tool designed to aid security analysts and incident responders in identifying Linux persistence mechanisms employed by attackers. Developed by 0xblake, this tool streamlines the process of detecting various persistence techniques on compromised Linux systems. Persistnux performs comprehensive checks across the system, generating detailed reports in both CSV and JSONL formats for further analysis. Its key feature is its dependency-free operation, relying solely on…
