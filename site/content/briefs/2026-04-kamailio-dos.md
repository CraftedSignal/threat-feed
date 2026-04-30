---
title: Kamailio Out-of-Bounds Access Denial of Service Vulnerability
slug: 2026-04-kamailio-dos
description: A remote attacker can exploit an out-of-bounds access vulnerability (CVE-2026-39863) in Kamailio versions prior to 6.1.1, 6.0.6, and 5.8.8 by sending a specially crafted data packet over TCP, causing a denial-of-service condition.
date: "2026-04-08T20:16:26Z"
severities:
  - high
type: advisory
types:
  - advisory
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

Kamailio, an open-source SIP signaling server, is susceptible to a denial-of-service vulnerability (CVE-2026-39863) affecting versions prior to 6.1.1, 6.0.6, and 5.8.8. The vulnerability stems from an out-of-bounds access issue in the core of Kamailio, which can be triggered by sending a specially crafted data packet over TCP.  This results in a process crash, effectively causing a denial-of-service condition.  The vulnerability specifically impacts Kamailio instances configured with TCP or TLS listeners, making them prime targets for exploitation.  Organizations using affected Kamailio versions are urged to upgrade to a patched release to mitigate the risk of service disruption.

## Attack Chain

1. The attacker identifies a Kamailio server running a vulnerable version (prior to 6.1.1, 6.0.6, or 5.8.8) with a TCP or TLS listener enabled.
2. The attacker crafts a malicious SIP packet specifically designed to exploit the out-of-bounds access vulnerability (CVE-2026-39863).
3. The attacker establishes a TCP connection to the Kamailio server on the designated SIP port (typically 5060 for TCP or 5061 for TLS).
4. The attacker sends the crafted malicious SIP packet over the established TCP connection.
5. The Kamailio server attempts to process the malicious packet.
6. Due to the out-of-bounds access vulnerability, the server attempts to read or write memory outside of the allocated buffer.
7. This out-of-bounds memory access leads to a segmentation fault or other memory corruption error.
8. The Kamailio process crashes, resulting in a denial-of-service condition, preventing legitimate SIP traffic from being processed.

## Impact

Successful exploitation of CVE-2026-39863 results in a denial-of-service condition, rendering the Kamailio server unavailable for processing SIP requests. This can disrupt VoIP services, impact call routing, and prevent users from making or receiving calls. The severity of the impact depends on the criticality of the Kamailio server within the organization's communication infrastructure. If a critical server fails, it could cause significant disruptions affecting hundreds or thousands of users.

## Recommendation

*   Upgrade Kamailio installations to version 6.1.1, 6.0.6, or 5.8.8 or later to patch CVE-2026-39863.
*   Implement rate limiting on SIP traffic at the firewall level to mitigate the impact of potential denial-of-service attacks targeting Kamailio.
*   Monitor Kamailio server logs for abnormal process crashes or restarts, which could indicate exploitation attempts.
*   Deploy the Sigma rule below to detect suspicious network activity associated with potential exploitation attempts against Kamailio servers with TCP or TLS listeners.
