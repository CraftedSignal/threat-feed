---
title: Warlock Group Deploys Web Shells, Tunnels, and Ransomware
slug: 2024-05-warlock-webshell-ransomware
description: The Warlock group utilizes web shells and tunneling to deploy ransomware within compromised environments, impacting victim data confidentiality and availability.
date: "2026-03-19T05:26:28Z"
severities:
  - critical
actors:
  - Warlock
tags:
  - webshell
  - ransomware
  - tunneling
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1572
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
references:
  - https://www.reddit.com/r/blueteamsec/comments/1rxruun/web_shells_tunnels_and_ransomware_dissecting_a/
  - https://www.trendmicro.com/en_us/research/26/c/dissecting-a-warlock-attack.html
rules:
  - title: Detect Web Shell Creation
    description: Detects the creation of common web shell file extensions in web server directories.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - file_event
      - windows
  - title: Detect Web Server Tunneling Activity
    description: Detects network connections from web servers to uncommon ports, indicative of tunneling.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1572
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

This brief describes a Warlock attack, as detailed in a Trend Micro analysis, involving the use of web shells, tunneling, and ransomware deployment. The Warlock group compromises systems by leveraging web shells for initial access and establishing tunnels for persistent access and command and control. This access is then used to deploy ransomware, encrypting critical data and demanding ransom payments from victims. The specific ransomware family and web shell variants employed are not detailed…
