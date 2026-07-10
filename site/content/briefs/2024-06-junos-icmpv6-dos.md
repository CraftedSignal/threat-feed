---
title: Juniper Junos OS SRX Series ICMPv6 Denial-of-Service Vulnerability (CVE-2026-33790)
slug: 2024-06-junos-icmpv6-dos
description: A specific, malformed ICMPv6 packet sent to a Juniper Networks Junos OS SRX Series device can trigger a crash and restart of the srxpfe process, leading to a sustained Denial of Service.
date: "2024-06-19T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - dos
  - icmpv6
  - junos
  - srx
  - nat64
vendors:
  - Juniper
products:
  - Junos OS
  - SRX Series
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
cves:
  - id: CVE-2026-33790
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33790
rules:
  - title: Detect Malformed ICMPv6 Packet to Junos SRX (DoS)
    description: Detects malformed ICMPv6 packets that could cause a Denial of Service on Juniper SRX series devices due to CVE-2026-33790.
    platform: sigma
    severity: high
    tactics:
      - availability
      - network
    techniques:
      - T1498
    data_sources:
      - network_connection
      - junos
  - title: Detect Repeated srxpfe Process Crashes
    description: Detects repeated crashes of the srxpfe process, which may indicate exploitation of CVE-2026-33790
    platform: sigma
    severity: medium
    tactics:
      - availability
      - process
    techniques:
      - T1498
    data_sources:
      - process_creation
      - junos
rules_count: 2
---

CVE-2026-33790 is a vulnerability affecting Juniper Networks Junos OS on SRX Series devices. The vulnerability resides in the flow daemon (flowd) and is triggered by sending a specific, malformed ICMPv6 packet to the device during NAT64 translation. This causes the srxpfe process to crash and restart. The continuous receipt and processing of these malformed packets will repeatedly crash the srxpfe process, resulting in a sustained Denial of Service (DoS) condition. The vulnerability is specific to ICMPv6 traffic and does not affect IPv4 or other IPv6 traffic types. Affected versions include versions before 21.2R3-S10, all versions of 21.3, versions 21.4 before 21.4R3-S12, all versions of 22.1, versions 22.2 before 22.2R3-S8, all versions of 22.4, versions 22.4 before 22.4R3-S9, versions 23.2 before 23.2R2-S6, versions 23.4 before 23.4R2-S7, versions 24.2 before 24.2R2-S3, versions 24.4 before 24.4R2-S3, and versions 25.2 before 25.2R1-S2, 25.2R2.

## Attack Chain

1. Attacker identifies a vulnerable Juniper SRX Series device running Junos OS with NAT64 enabled.
2. The attacker crafts a specific, malformed ICMPv6 packet.
3. The attacker sends the malformed ICMPv6 packet to the SRX device.
4. The SRX device receives the ICMPv6 packet and attempts NAT64 translation.
5. Due to the malformed packet, the flowd process encounters an improper check condition.
6. The srxpfe process crashes as a result of the malformed ICMPv6 packet.
7. The srxpfe process restarts automatically.
8. The attacker continuously sends malformed ICMPv6 packets to repeatedly crash the srxpfe process, sustaining a Denial-of-Service condition.

## Impact

Successful exploitation of this vulnerability leads to a Denial-of-Service condition on the affected Juniper SRX Series device. This can disrupt network services, impacting connectivity and availability for legitimate users. The repeated crashing of the srxpfe process can severely degrade device performance and potentially lead to complete service outage. The number of potential victims is dependent on the number of deployed, vulnerable Juniper SRX series devices with NAT64 enabled.

## Recommendation

*   Apply the appropriate patch or upgrade to a fixed version of Junos OS on SRX Series devices as specified in the Juniper advisory to remediate CVE-2026-33790.
*   Monitor network traffic for unusual or malformed ICMPv6 packets destined for SRX devices performing NAT64, as this may indicate exploitation attempts, and deploy the provided Sigma rule to detect such activity.
*   Implement rate limiting for ICMPv6 traffic at the network perimeter to mitigate the impact of potential DoS attacks targeting this vulnerability, preventing the continuous crashing of the srxpfe process.
