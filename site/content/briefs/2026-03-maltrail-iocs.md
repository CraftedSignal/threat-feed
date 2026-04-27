---
title: Maltrail IOC Feed Update for Multiple Threats
slug: 2026-03-maltrail-iocs
description: This brief summarizes IOCs extracted from the Maltrail feed on March 15, 2026, covering domains and URLs associated with threats targeting macOS and Android platforms, including OSX_Atomic, FakeApp, Android_Joker, Lummack2, APT_Sidewinder, APT_Kimsuky, and Hak5Cloud_C2.
date: "2026-03-15T21:00:08Z"
severities:
  - medium
tags:
  - maltrail
  - ioc
  - osx
  - android
  - apt
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
references:
  - https://www.circl.lu/doc/misp/feed-osint/878f5b33-0fcf-4191-8295-4bcddeb6437a.json
  - https://api.github.com/repos/stamparm/maltrail/commits/a3681b0b82849e400e3b2ffd5b30608abf1bb7f1
  - https://api.github.com/repos/stamparm/maltrail/commits/b681d4bce01b9723fab2ce0ea10133353f943434
  - https://api.github.com/repos/stamparm/maltrail/commits/2065e8ab6f15b8cdeeb24a07fab8d849fc9e6935
  - https://api.github.com/repos/stamparm/maltrail/commits/75f0bd1595532bf7fafcf9cfcc1caf4b1e6b4267
  - https://api.github.com/repos/stamparm/maltrail/commits/fcf8b4ecf7b8aed41bb22bfe41fe52ea3c076f40
  - https://api.github.com/repos/stamparm/maltrail/commits/ce05d11717590e58ed4f2ff73759262c90789426
  - https://api.github.com/repos/stamparm/maltrail/commits/83fd2c39f154b193baaf1753656a598bbbf276b9
  - https://api.github.com/repos/stamparm/maltrail/commits/23476cd55bd5a2e74485e8bd710c9b9b4cdfcfc5
  - https://api.github.com/repos/stamparm/maltrail/commits/fd7a3895e500e82b02c6b97f9de338c598120ad8
  - https://api.github.com/repos/stamparm/maltrail/commits/8273ebec7b56bffd4c5c44eb7b22e7f5021fdd39
ioc_counts:
  domain: 40
  url: 10
rules:
  - title: Detect Network Connection to Hak5Cloud C2 Domain
    description: Detects network connections to the Hak5Cloud command and control domain.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Connection to APT_Sidewinder Domain
    description: Detects network connections to a domain associated with APT_Sidewinder.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Connection to FakeApp Domains
    description: Detects network connections to domains associated with FakeApp malware.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

This threat brief highlights indicators of compromise (IOCs) identified on March 15, 2026, through the Maltrail feed. The identified IOCs are associated with a variety of threat actors and malware families, targeting both macOS and Android operating systems. The threats include OSX_Atomic, which potentially delivers malware to macOS systems; FakeApp, used for deceptive applications; Android_Joker, a known Android malware family; Lummack2, an information stealer; APT_Sidewinder, an advanced…
