---
title: Firebird Server Denial-of-Service Vulnerability (CVE-2026-28224)
slug: 2026-04-firebird-dos
description: An unauthenticated attacker can trigger a denial-of-service condition on vulnerable Firebird servers by sending a specially crafted op_crypt_key_callback packet, leading to a null pointer dereference and server crash.
date: "2026-04-18T10:00:00Z"
severities:
  - high
tags:
  - cve-2026-28224
  - denial-of-service
  - firebird
  - database
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-28224
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-28224
rules:
  - title: Detect Unauthenticated Firebird Crypt Callback
    description: Detects attempts to exploit CVE-2026-28224 by identifying unauthenticated op_crypt_key_callback packets sent to Firebird servers.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Firebird Server Crash
    description: Detects potential Firebird server crashes by monitoring for process termination events with specific exit codes indicative of a crash.
    platform: sigma
    severity: critical
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-28224 describes a denial-of-service vulnerability affecting Firebird, an open-source relational database management system. The vulnerability exists in versions prior to 5.0.4, 4.0.7, and 3.0.14. An unauthenticated attacker can exploit this vulnerability by sending a crafted `op_crypt_key_callback` packet to the server. When the server receives this packet without prior authentication, the `port_server_crypt_callback` handler is not initialized, resulting in a null pointer dereference…
