---
title: SoftEtherVPN Pre-Authentication Denial-of-Service Vulnerability (CVE-2026-39312)
slug: 2026-04-softether-dos
description: SoftEtherVPN version 5.2.5188 and earlier is vulnerable to a pre-authentication denial-of-service attack where an unauthenticated remote attacker can crash the vpnserver process by sending a malformed EAP-TLS packet over raw L2TP (UDP/1701), terminating all active VPN sessions.
date: "2026-04-07T17:16:36Z"
severities:
  - high
tags:
  - dos
  - softethervpn
  - cve-2026-39312
  - l2tp
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
cves:
  - id: CVE-2026-39312
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39312
  - https://github.com/SoftEtherVPN/SoftEtherVPN/security/advisories/GHSA-q5g3-qhc6-pr3h
rules:
  - title: Detect SoftEtherVPN Malformed EAP-TLS Packet
    description: Detects potentially malformed EAP-TLS packets sent to SoftEtherVPN servers over UDP/1701, which could indicate a denial-of-service attempt.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - firewall
  - title: Detect SoftEtherVPN Server Process Crash
    description: Detects a sudden termination of the SoftEtherVPN server process, which could be a result of CVE-2026-39312 exploitation.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

SoftEtherVPN is an open-source, cross-platform, multi-protocol VPN program. A pre-authentication denial-of-service vulnerability, identified as CVE-2026-39312, affects SoftEther VPN Developer Edition 5.2.5188 and likely earlier versions. Disclosed on April 7, 2026, this vulnerability allows an unauthenticated remote attacker to crash the `vpnserver` process, effectively terminating all active VPN sessions. The attack vector involves sending a single malformed EAP-TLS packet over raw L2TP…
