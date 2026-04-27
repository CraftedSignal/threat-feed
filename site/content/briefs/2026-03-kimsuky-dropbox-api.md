---
title: Kimsuky Malware Using Dropbox API for Command and Control
slug: 2026-03-kimsuky-dropbox-api
description: Kimsuky is using malware that leverages the Dropbox API for command and control, enabling file exfiltration and remote code execution.
date: "2026-03-19T12:00:00Z"
severities:
  - high
actors:
  - Kimsuky
tags:
  - kimsuky
  - dropbox
  - api
  - command-and-control
  - exfiltration
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://sect.iij.ad.jp/blog/2026/03/dropbox-api-kimsuky-malware/
  - https://www.reddit.com/r/blueteamsec/comments/1rxe9cf/dropbox_api%E3%82%92%E4%BD%BF%E7%94%A8%E3%81%99%E3%82%8Bkimsuky%E3%81%AE%E3%83%9E%E3%83%AB%E3%82%A6%E3%82%A7%E3%82%A2_kimsuky_malware/
rules:
  - title: Detect Suspicious Dropbox API Usage
    description: Detects processes making API calls to Dropbox, which could indicate malware using Dropbox for C2.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Process Creating Network Connections to Dropbox API
    description: Detects a process creation event where the created process then connects to the Dropbox API
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Kimsuky, a North Korean APT group, has been observed utilizing malware that leverages the Dropbox API for command and control (C2). This allows the malware to blend in with legitimate network traffic, making detection more challenging. The malware uses the Dropbox API to upload stolen data and download commands from the attackers. This method provides a covert channel for exfiltration and control, bypassing traditional network-based security measures. The group has been known to target South…
