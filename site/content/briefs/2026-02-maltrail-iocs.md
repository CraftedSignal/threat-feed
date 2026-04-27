---
title: Maltrail IOCs for Android Joker, APT Lazarus, UNC2465, and Powershell Injector
slug: 2026-02-maltrail-iocs
description: This brief covers IOCs associated with Android Joker malware, APT Lazarus group, APT UNC2465 activity, and PowerShell Injector campaigns identified by Maltrail on February 25, 2026.
date: "2026-02-25T22:01:17Z"
severities:
  - medium
tags:
  - maltrail
  - ioc
  - android_joker
  - apt_lazarus
  - unc2465
  - powershell_injector
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.circl.lu/doc/misp/feed-osint/6af94a64-39c8-4066-a702-7ad7b9cc5cdd.json
ioc_counts:
  domain: 42
  ip: 1
  url: 6
rules:
  - title: Detect PowerShell Encoded Commands
    description: Detects PowerShell commands using the -enc or -EncodedCommand parameters, which are often used to obfuscate malicious scripts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Outbound Connections to APT Lazarus IP
    description: Detects network connections to the IP address associated with APT Lazarus activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Connection to Newly Observed Domains
    description: Detects network connections to domains observed in the Maltrail feed, which could indicate new or emerging threats.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1568.002
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

This threat brief summarizes indicators of compromise (IOCs) identified by Maltrail on February 25, 2026, linking to several distinct threat actors and campaigns. These include the Android Joker malware known for its malicious billing fraud, APT Lazarus group, APT UNC2465, and campaigns involving the use of PowerShell injectors. The IOCs consist of domains and URLs related to network activity and external analysis of these threats. Notably, a large number of domains were identified without…
