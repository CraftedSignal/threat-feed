---
title: 'Maltrail IOCs Report: Tracking Multiple Threat Actors'
slug: 2026-02-maltrail-iocs
description: This brief analyzes IOCs aggregated by Maltrail on February 27, 2026, highlighting network activity associated with diverse threat actors including APT_UNC2465, Lazarus Group, Gorat, APT_Bitter, Android_Joker, PowerShell Injector, SmokeLoader, and FakeApp campaigns targeting various sectors.
date: "2026-02-27T23:00:14Z"
severities:
  - medium
tags:
  - maltrail
  - threat-intelligence
  - apt
  - malware
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1001
    technique_name: Data Obfuscation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
references:
  - https://www.circl.lu/doc/misp/feed-osint/ca644701-62d1-4217-ada4-37452e8086db.json
  - https://api.github.com/repos/stamparm/maltrail/commits/0646683ef79252a23e46ab0f0c2f5cd19622153a
  - https://api.github.com/repos/stamparm/maltrail/commits/ef8592c301ca981ee5e763e64a2799a42dfb624a
  - https://api.github.com/repos/stamparm/maltrail/commits/9b786d496f9492f593d4f4d4d65f55da0fe1f8ee
  - https://api.github.com/repos/stamparm/maltrail/commits/a6a5d4fc2e913d96182c8ba9c1cf9296ae1d8c3e
  - https://api.github.com/repos/stamparm/maltrail/commits/3f6f94d4cbe5ca9362428adb4dee7084d1cdd24b
  - https://api.github.com/repos/stamparm/maltrail/commits/580ed2e5cc6de73363f5768a87fbdd3339dc2d7c
  - https://api.github.com/repos/stamparm/maltrail/commits/1aef6ec81fe3d2f652843e6dbe91455a2cd62f5c
  - https://api.github.com/repos/stamparm/maltrail/commits/fc046d4c30e9cf55674bf051ff38d5ddd5ded3d6
  - https://api.github.com/repos/stamparm/maltrail/commits/d80f240b6a29965ab001b54937bd0551badb89b4
  - https://api.github.com/repos/stamparm/maltrail/commits/0b2c6651676f745850e5150528d491647cdb0f53
  - https://api.github.com/repos/stamparm/maltrail/commits/032c33b2917a05e61f48ff99ab0faaf523441536
ioc_counts:
  domain: 24
  ip: 3
rules:
  - title: Detect Network Connection to PowerShell Injector Domains
    description: Detects network connections to domains associated with PowerShell Injector campaigns, indicating potential command and control activity.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Network Connection to FakeApp Domains
    description: Detects network connections to domains associated with FakeApp campaigns, indicating potential communication with malicious infrastructure.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Network Connection to msftconnecttest Domains
    description: Detects network connections to domains used by the Gorat group, masquerading as Microsoft connection tests.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

This threat brief is based on an IOC feed from Maltrail, dated February 27, 2026, which aggregates indicators related to various threat actors and malware campaigns. The tracked actors include APT_UNC2465, Lazarus Group, Gorat, APT_Bitter, Android_Joker, PowerShell Injector, SmokeLoader, and FakeApp. The IOCs primarily consist of domains and IP addresses associated with these groups' network infrastructure and malware distribution. These campaigns are likely targeting a wide range of victims…
