---
title: SoftEtherVPN Pre-Authentication Denial-of-Service Vulnerability (CVE-2026-39312)
slug: 2026-04-softether-dos
description: SoftEtherVPN version 5.2.5188 and earlier is vulnerable to a pre-authentication denial-of-service attack where an unauthenticated remote attacker can crash the vpnserver process by sending a malformed EAP-TLS packet over raw L2TP (UDP/1701), terminating all active VPN sessions.
date: "2026-04-07T17:16:36Z"
severities:
  - high
type: advisory
types:
  - advisory
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

SoftEtherVPN is an open-source, cross-platform, multi-protocol VPN program. A pre-authentication denial-of-service vulnerability, identified as CVE-2026-39312, affects SoftEther VPN Developer Edition 5.2.5188 and likely earlier versions. Disclosed on April 7, 2026, this vulnerability allows an unauthenticated remote attacker to crash the `vpnserver` process, effectively terminating all active VPN sessions. The attack vector involves sending a single malformed EAP-TLS packet over raw L2TP, specifically UDP port 1701. Exploitation of this vulnerability requires no prior authentication, making it easily exploitable and posing a significant risk to organizations relying on SoftEtherVPN for secure remote access. The impact can range from temporary service disruption to complete VPN infrastructure unavailability.

## Attack Chain

1. An unauthenticated attacker identifies a vulnerable SoftEtherVPN server (version 5.2.5188 or earlier) exposed over UDP port 1701.
2. The attacker crafts a malformed EAP-TLS packet.
3. The attacker sends the crafted EAP-TLS packet over raw L2TP (UDP/1701) to the target VPN server.
4. The SoftEtherVPN server receives the malformed packet.
5. Due to the vulnerability, the `vpnserver` process attempts to process the malformed packet.
6. The processing of the malformed packet triggers a memory allocation issue (CWE-789), causing the `vpnserver` process to crash.
7. All active VPN sessions are terminated abruptly as the `vpnserver` process is no longer running.
8. Legitimate users are disconnected and unable to establish new VPN connections, resulting in a denial-of-service condition.

## Impact

Successful exploitation of CVE-2026-39312 results in a denial-of-service condition, disrupting VPN services and preventing legitimate users from accessing internal resources. The vulnerability allows an unauthenticated attacker to remotely crash the VPN server, potentially impacting any organization using SoftEtherVPN for remote access. The impact is a complete outage of VPN services until the `vpnserver` process is manually restarted, leading to potential loss of productivity and business disruption.

## Recommendation

*   Upgrade SoftEtherVPN to a version later than 5.2.5188 to patch CVE-2026-39312.
*   Monitor network traffic for unusual or malformed EAP-TLS packets on UDP port 1701, using the "Detect SoftEtherVPN Malformed EAP-TLS Packet" Sigma rule.
*   Implement rate limiting on UDP port 1701 to mitigate the impact of a potential denial-of-service attack.
