---
title: Iranian Botnet Operation Exposed via Open Directory
slug: 2024-01-iranian-botnet
description: An Iranian botnet operation utilizing a 15-node relay network and active C2 infrastructure was exposed through an open directory.
date: "2026-03-17T19:15:28Z"
severities:
  - medium
tags:
  - botnet
  - iran
  - C2
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://www.reddit.com/r/blueteamsec/comments/1rwgb2t/iranian_botnet_exposed_via_open_directory_15node/
  - https://hunt.io/blog/iran-botnet-operation-open-directory
ioc_counts:
  domain: 1
rules:
  - title: Detect Outbound Connection to Hunt.io
    description: Detects outbound network connections to hunt.io, a domain related to the Iranian botnet operation.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 1
---

A blog post on hunt.io details an Iranian botnet operation discovered through an open directory. The operation involves a 15-node relay network, suggesting a focus on obfuscation and resilience. The existence of an active Command and Control (C2) infrastructure indicates ongoing malicious activity. The exposure of these details allows defenders to gain insights into the botnet's architecture and potentially disrupt its operations. While the specific targeting and malware used remain unclear…
