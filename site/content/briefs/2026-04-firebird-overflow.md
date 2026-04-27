---
title: Firebird Database Server Slice Packet Deserialization Buffer Overflow
slug: 2026-04-firebird-overflow
description: Firebird versions before 5.0.4, 4.0.7, and 3.0.14 are vulnerable to a buffer overflow in the xdr_datum() function during slice packet deserialization, enabling unauthenticated attackers to cause a crash or potentially achieve arbitrary code execution by sending a malicious packet.
date: "2026-04-17T19:16:36Z"
severities:
  - critical
tags:
  - cve-2026-33337
  - firebird
  - buffer-overflow
  - denial-of-service
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1210
    technique_name: Exploitation of Remote Services
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.001
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-33337
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33337
rules:
  - title: Detect Firebird Slice Packet Overflow Attempt
    description: Detects potential exploitation attempts of the Firebird slice packet deserialization buffer overflow vulnerability (CVE-2026-33337) by identifying network connections with unusually large packet sizes to the Firebird server port.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1210
      - T1499.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Firebird Process Crash
    description: Detects a Firebird process crash based on event logs indicating an unexpected process termination. This could be indicative of successful exploitation of CVE-2026-33337.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Firebird, a widely used open-source relational database management system, is susceptible to a critical buffer overflow vulnerability. Present in versions prior to 5.0.4, 4.0.7, and 3.0.14, the vulnerability resides within the `xdr_datum()` function, responsible for deserializing slice packets. This function fails to adequately validate the length of cstring data against the slice descriptor bounds. Consequently, an attacker can craft a malicious packet containing an oversized cstring, leading…
