---
title: DarkSword iOS Exploit Chain Proliferation
slug: 2026-03-darksword-ios
description: The DarkSword exploit chain targets iOS versions 18 and under by exploiting a WebKit vulnerability, and is being adopted by multiple threat actors for initial access and execution.
date: "2026-03-19T12:00:00Z"
severities:
  - high
tags:
  - ios
  - exploit
  - webkit
  - darksword
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://www.reddit.com/r/cybersecurity/comments/1rxa3hw/the_proliferation_of_darksword_ios_exploit_chain/
  - https://cloud.google.com/blog/topics/threat-intelligence/darksword-ios-exploit-chain
rules:
  - title: Detect Suspicious Process Execution from Safari/WebKit
    description: Detects suspicious process execution originating from Safari or WebKit processes, potentially indicating exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1189
    data_sources:
      - process_creation
      - macos
rules_count: 1
---

The DarkSword exploit chain is a recently identified threat targeting mobile devices running iOS 18 and earlier. This exploit chain leverages a vulnerability within the WebKit rendering engine, commonly used in Safari and other applications. While the specifics of the vulnerability are not detailed in this brief, its exploitation leads to arbitrary code execution within the context of the targeted application or the operating system itself. Multiple threat actors are now incorporating DarkSword…
