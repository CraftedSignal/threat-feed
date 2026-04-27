---
title: Mesop Framework WebSocket Denial-of-Service Vulnerability (CVE-2026-34824)
slug: 2026-04-mesop-dos
description: An unauthenticated attacker can exploit an uncontrolled resource consumption vulnerability in Mesop versions 1.2.3 to 1.2.4 by sending a rapid succession of WebSocket messages, leading to thread exhaustion and a denial-of-service condition.
date: "2026-04-04T12:00:00Z"
severities:
  - high
tags:
  - denial-of-service
  - websocket
  - cve-2026-34824
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34824
rules:
  - title: Detect Mesop Excessive WebSocket Connections
    description: Detects a high number of WebSocket connections to a Mesop server from a single source IP, indicating potential DoS exploitation.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - linux
  - title: Detect Mesop Thread Exhaustion via Process Creation
    description: Detects a high number of process creations potentially related to thread spawning by a Mesop application, indicating potential DoS exploitation.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Mesop, a Python-based UI framework, is vulnerable to a denial-of-service (DoS) attack due to uncontrolled resource consumption in its WebSocket implementation. Specifically, versions 1.2.3 and 1.2.4 are affected. An unauthenticated attacker can exploit this vulnerability (CVE-2026-34824) by sending a rapid succession of WebSocket messages. The server, in turn, spawns an unbounded number of operating system threads to handle these messages. This leads to thread exhaustion and Out of Memory (OOM)…
