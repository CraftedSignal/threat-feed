---
title: Kamailio Out-of-Bounds Access Denial of Service Vulnerability
slug: 2026-04-kamailio-dos
description: A remote attacker can exploit an out-of-bounds access vulnerability (CVE-2026-39863) in Kamailio versions prior to 6.1.1, 6.0.6, and 5.8.8 by sending a specially crafted data packet over TCP, causing a denial-of-service condition.
date: "2026-04-08T20:16:26Z"
severities:
  - high
tags:
  - dos
  - cve-2026-39863
  - kamailio
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
cves:
  - id: CVE-2026-39863
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39863
  - https://github.com/kamailio/kamailio/security/advisories/GHSA-2wj4-f825-2h2f
rules:
  - title: Detect Kamailio DoS Attempt via Crafted SIP Packet
    description: Detects potential denial-of-service attempts against Kamailio servers by monitoring for suspicious network connections on TCP ports commonly used for SIP traffic (5060, 5061).
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - linux
  - title: Detect Kamailio Process Crash
    description: Detects potential denial-of-service attempts against Kamailio by monitoring process termination events.
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

Kamailio, an open-source SIP signaling server, is susceptible to a denial-of-service vulnerability (CVE-2026-39863) affecting versions prior to 6.1.1, 6.0.6, and 5.8.8. The vulnerability stems from an out-of-bounds access issue in the core of Kamailio, which can be triggered by sending a specially crafted data packet over TCP.  This results in a process crash, effectively causing a denial-of-service condition.  The vulnerability specifically impacts Kamailio instances configured with TCP or TLS…
