---
title: Mirai C2 Remote Denial-of-Service Vulnerability (CVE-2024-45163)
slug: 2026-03-mirai-c2-dos
description: CVE-2024-45163 is a remote denial-of-service vulnerability affecting Mirai command and control (C2) infrastructure, potentially disrupting botnet operations and related malicious activities.
date: "2026-03-16T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2024-45163
  - mirai
  - dos
  - iot
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://www.reddit.com/r/netsec/comments/1ru6xxl/cve202445163_remote_dos_in_mirai_c2_research/
  - https://flowtriq.com/blog/cve-2024-45163
rules:
  - title: Generic DoS Detection - High Volume of Connections from Single Source
    description: Detects a high volume of connections originating from a single IP address, which could indicate a denial-of-service attack
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - zeek
  - title: Detect Mirai C2 Communication Attempts
    description: Detects attempts to communicate with known Mirai C2 servers
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071
    data_sources:
      - dns_query
      - suricata
rules_count: 2
---

CVE-2024-45163 describes a remote denial-of-service vulnerability present within Mirai C2 infrastructure. While specific details regarding the vulnerability itself are not provided in this brief, the existence of a publicly known vulnerability in Mirai C2 servers is significant. Mirai is a well-known IoT botnet that has been used in numerous large-scale DDoS attacks. Exploitation of this vulnerability could allow attackers to disrupt Mirai botnet operations, potentially mitigating ongoing…
