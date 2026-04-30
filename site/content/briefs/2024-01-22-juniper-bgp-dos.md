---
title: Juniper Junos OS and Junos OS Evolved BGP Session Reset Denial of Service (CVE-2026-33797)
slug: 2024-01-22-juniper-bgp-dos
description: CVE-2026-33797 is an improper input validation vulnerability in Juniper Networks Junos OS and Junos OS Evolved that allows an unauthenticated adjacent attacker to reset established BGP sessions via a specific BGP packet, leading to a denial of service condition.
date: "2026-04-09T22:16:29Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - cve-2026-33797
  - denial-of-service
  - juniper
  - bgp
  - network
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
cves:
  - id: CVE-2026-33797
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33797
rules:
  - title: Detect Excessive BGP Session Resets
    description: Detects a high number of BGP session resets within a short timeframe, potentially indicating a denial-of-service attack.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - juniper
  - title: BGP Session Reset from New Source IP
    description: Detects BGP session resets originating from a source IP address that hasn't been seen before.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - network_connection
      - juniper
  - title: Detect BGP Anomalous Packet Size
    description: Detects BGP packets with sizes outside the expected range, potentially indicating a crafted malicious packet
    platform: sigma
    severity: low
    tactics:
      - denial_of_service
    techniques:
      - T1498
    data_sources:
      - network_connection
      - juniper
rules_count: 3
---

CVE-2026-33797 is a vulnerability affecting Juniper Networks Junos OS and Junos OS Evolved versions 25.2 before 25.2R2 and 25.2-EVO before 25.2R2-EVO, respectively. It stems from improper input validation within the Border Gateway Protocol (BGP) handling. An unauthenticated, adjacent attacker can exploit this flaw by sending a crafted BGP packet to an already established BGP session. This malicious packet causes the targeted BGP session to reset, leading to a Denial of Service (DoS). Repeated transmission of the crafted packet can sustain the DoS condition. Both external BGP (eBGP) and internal BGP (iBGP) sessions are susceptible, and the vulnerability impacts both IPv4 and IPv6 network configurations. This vulnerability poses a risk to network stability and availability.

## Attack Chain

1.  Attacker identifies a vulnerable Juniper device running Junos OS or Junos OS Evolved versions 25.2 prior to 25.2R2 or 25.2-EVO prior to 25.2R2-EVO.
2.  The attacker establishes network adjacency to the targeted device, allowing for direct BGP communication.
3.  The attacker crafts a specific, but genuine, BGP packet designed to exploit the improper input validation vulnerability.
4.  The attacker sends the crafted BGP packet to an already established BGP session on the target device.
5.  Upon receiving the malicious packet, the vulnerable Junos OS or Junos OS Evolved instance improperly processes it.
6.  Due to the input validation failure, the targeted BGP session is forcibly reset.
7.  The attacker repeats the process of sending the crafted BGP packet to continuously reset the BGP session.
8.  The repeated session resets cause a sustained Denial of Service (DoS), disrupting network routing and connectivity.

## Impact

Successful exploitation of CVE-2026-33797 leads to a denial-of-service condition affecting BGP routing. By repeatedly sending crafted BGP packets, an attacker can disrupt network connectivity and stability. The impact is a loss of routing functionality for networks relying on the targeted BGP sessions. The number of potential victims is broad, including any organization using vulnerable versions of Junos OS or Junos OS Evolved. This can result in service outages, impaired communication, and potential financial losses.

## Recommendation

*   Upgrade Junos OS to version 25.2R2 or later to remediate CVE-2026-33797 (see references).
*   Upgrade Junos OS Evolved to version 25.2R2-EVO or later to remediate CVE-2026-33797 (see references).
*   Deploy the Sigma rule provided to detect unusual BGP reset activity in network traffic (see rules).
*   Monitor network traffic for unexpected BGP session resets originating from adjacent networks.
