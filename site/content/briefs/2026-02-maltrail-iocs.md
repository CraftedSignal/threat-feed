---
title: Maltrail IOCs for Remcos RAT and EK_ClearFake
slug: 2026-02-maltrail-iocs
description: This brief summarizes IOCs related to Remcos RAT, a remote access trojan, and EK_ClearFake, an exploit kit, as identified by Maltrail on February 26, 2026.
date: "2026-02-26T17:00:11Z"
severities:
  - high
tags:
  - remcos
  - clearfake
  - exploit-kit
  - rat
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://www.circl.lu/doc/misp/feed-osint/9291457f-54be-4e1d-b239-3562e18112d7.json
  - https://api.github.com/repos/stamparm/maltrail/commits/0c6667175dd9fba7698bbf1bdf849297b605a2e3
  - https://x.com/BlinkzSec/status/2026899651345993936
  - https://www.virustotal.com/gui/file/4f0c95a1885411100649bf8150c2f189dc0941ac569b801b3765d1ca64b760dc/detection
  - https://api.github.com/repos/stamparm/maltrail/commits/210c5c1185382eb070ddcbbee197d498b2870bce
  - https://api.github.com/repos/stamparm/maltrail/commits/89ff2ed1d3a60e8ab5104cc8b6f398be6d6045ae
ioc_counts:
  domain: 43
  ip: 1
  url: 5
rules:
  - title: Detect Remcos RAT DNS Query
    description: Detects DNS queries to the Remcos RAT domain.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - dns_query
      - windows
  - title: Detect EK_ClearFake Domain Connection
    description: Detects network connections to EK_ClearFake domains.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - network_connection
      - windows
  - title: Detect Connection to EK_ClearFake snoozetrap.in.net Domains
    description: Detects connections to EK_ClearFake domains ending in snoozetrap.in.net.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

This brief is based on IOCs identified by Maltrail on February 26, 2026. The IOCs are associated with two distinct threats: Remcos RAT and EK_ClearFake. Remcos RAT is a commercially available remote access trojan often used for malicious purposes, including data theft and surveillance. EK_ClearFake is an exploit kit known for distributing various malware through compromised websites. The domains associated with EK_ClearFake are likely used to host or redirect to landing pages containing…
