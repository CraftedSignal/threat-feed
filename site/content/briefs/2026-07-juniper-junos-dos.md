---
title: 'CVE-2026-57023: Juniper Junos OS TCP Proxy Denial of Service'
slug: 2026-07-juniper-junos-dos
description: An Improper Validation of Specified Quantity in Input vulnerability (CVE-2026-57023) in the TCP proxy plugin of Juniper Networks Junos OS on MX Series with SPC3 and SRX Series allows an unauthenticated, network-based attacker to cause a complete Denial of Service (DoS) by sending a specifically malformed TCP header packet, crashing the flow processing daemon (flowd) until automated recovery.
date: "2026-07-09T22:20:35Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - network
  - juniper
vendors:
  - Juniper Networks
products:
  - Junos OS on MX Series with SPC3
  - Junos OS on SRX Series
affected_os:
  - Junos OS
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: An Improper Validation of Specified Quantity in Input vulnerability ... will cause flow processing daemon (flowd) to crash and restart. This causes a complete service outage until the system has automatically recovered.
    confidence_band: high
cves:
  - id: CVE-2026-57023
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57023
---

A critical Improper Validation of Specified Quantity in Input vulnerability, identified as CVE-2026-57023, has been discovered in the TCP proxy plugin of Juniper Networks Junos OS. This flaw affects MX Series devices equipped with SPC3 cards and SRX Series firewalls. An unauthenticated, network-based attacker can exploit this vulnerability by transmitting a TCP packet containing a specifically malformed TCP header. When the TCP proxy is actively engaged in a flow session, particularly for services such as Application Layer Gateways (ALGs), Advanced Anti-Malware, ICAP, or UTM, this malformed packet triggers a crash of the flow processing daemon (flowd). The resulting crash causes a complete service outage and leads to a Denial of Service (DoS) until the system automatically recovers. The vulnerability impacts Junos OS 23.4 versions prior to 23.4R2-S7, 24.2 versions prior to 24.2R2-S4, 24.4 versions prior to 24.4R2-S3, and 25.2 versions prior to 25.2R2.

## Attack Chain

1. An unauthenticated attacker sends a specially crafted TCP packet over the network towards an internet-facing Juniper device running affected Junos OS versions.
2. The Juniper device, specifically an MX Series with SPC3 or SRX Series, has its TCP proxy engaged to support services such as ALGs, Advanced Anti-Malware, ICAP, or UTM.
3. The crafted TCP packet contains a malformed TCP header, designed to exploit the improper validation vulnerability.
4. The device's flow processing daemon (flowd) receives the malformed TCP packet as part of an active flow session.
5. During the processing of the malformed TCP header, the `flowd` component encounters an invalid state or condition due to the vulnerability.
6. This improper validation causes the `flowd` daemon to crash.
7. The system automatically initiates a restart of the `flowd` daemon to restore functionality.
8. During the period of the crash and subsequent restart, a complete service outage occurs, resulting in a Denial of Service (DoS) for the affected device.

## Impact

The successful exploitation of CVE-2026-57023 results in a complete Denial of Service (DoS) for the affected Juniper Networks Junos OS devices. This DoS is caused by the crashing and restarting of the flow processing daemon (flowd), which is critical for network traffic handling. Organizations relying on these devices for routing, security, or other network services will experience a full service outage until the system automatically recovers. The CVSS v3.1 Base Score of 7.5 indicates a high severity due to the unauthenticated nature of the attack and the complete loss of availability.

## Recommendation

* Prioritize patching CVE-2026-57023 immediately on all affected Juniper Networks Junos OS devices.
* Upgrade Junos OS on MX with SPC3 and SRX Series to versions 23.4R2-S7, 24.2R2-S4, 24.4R2-S3, 25.2R2, or later to mitigate CVE-2026-57023.
