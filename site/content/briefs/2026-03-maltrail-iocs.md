---
title: Maltrail IOCs Targeting Multiple Threat Actors
slug: 2026-03-maltrail-iocs
description: This brief analyzes IOCs aggregated by Maltrail on March 13, 2026, revealing network activity associated with multiple threat actors including UNC2465, SideWinder, 0ktapus, LummaC2, XWorm, PowerShell Injector, CyberStrikeAI, and others, indicating potential widespread targeting and diverse attack vectors.
date: "2026-03-13T23:00:14Z"
severities:
  - medium
tags:
  - maltrail
  - ioc
  - threat-actor
  - network-traffic
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
references:
  - https://www.circl.lu/doc/misp/feed-osint/63adc937-9506-463f-9d28-ec2e3ac56093.json
ioc_counts:
  domain: 23
  ip: 9
rules:
  - title: Detect Connections to DuckDNS Domains
    description: Detects connections to domains hosted on duckdns.org, often used for dynamic DNS by malware.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Connections to Known Malicious IPs
    description: Detects connections to a list of known malicious IP addresses.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

On March 13, 2026, Maltrail, an open-source malicious traffic detection system, identified a series of IOCs associated with various threat actors and campaigns. This intelligence brief focuses on several notable clusters of activity, including those linked to APT groups like UNC2465 and SideWinder, as well as malware families such as LummaC2, XWorm, and PowerShell Injector. The identified IOCs consist primarily of domains and IP addresses used for command and control (C2) or other malicious…
