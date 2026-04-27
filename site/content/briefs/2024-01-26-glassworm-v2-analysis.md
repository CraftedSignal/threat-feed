---
title: GlassWorm V2 Infrastructure Rotation and GitHub Injection Analysis
slug: 2024-01-26-glassworm-v2-analysis
description: Analysis of GlassWorm V2 reveals infrastructure rotation and GitHub injection techniques.
date: "2026-03-15T13:51:21Z"
severities:
  - medium
tags:
  - malware
  - github
  - infrastructure
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1573
    technique_name: Encrypted Channel
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
references:
  - https://www.reddit.com/r/netsec/comments/1ruekc5/glassworm_v2_analysis_part_2_infrastructure/
  - https://codeberg.org/tip-o-deincognito/glassworm-writeup/src/branch/main/PART2.md
rules:
  - title: Detect Outbound Network Connection to Newly Registered Domain
    description: Detects outbound network connections to newly registered domains, potentially indicating C2 communication.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1573.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Unusual Process Accessing GitHub API
    description: Detects processes that are not commonly associated with GitHub API usage but are making requests to it, potentially indicating malicious code injection or data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1573.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

This threat brief summarizes an analysis of GlassWorm V2, focusing on its infrastructure rotation and GitHub injection techniques. While specific details regarding the threat actor and initial attack vectors are not provided in this analysis, the report highlights the malware's ability to dynamically change its command and control (C2) infrastructure and potentially leverage GitHub for code injection or storage. Understanding these techniques is crucial for defenders to develop robust detection…
