---
title: Hirschmann HiOS EtherNet/IP Stack Denial-of-Service Vulnerability (CVE-2020-37216)
slug: 2026-04-hios-dos
description: A denial-of-service vulnerability in Hirschmann HiOS devices allows remote attackers to crash or hang the device by sending crafted UDP EtherNet/IP packets with invalid length fields.
date: "2026-04-03T21:17:08Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - dos
  - cve-2020-37216
  - network
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2020-37216
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2020-37216
  - https://assets.belden.com/m/3d3e2cbfa4860258/original/Belden-Security-Bulletin-BSECV-2019-14.pdf
  - https://www.vulncheck.com/advisories/hirschmann-hios-ethernet-ip-stack-denial-of-service
rules:
  - title: Detect Suspiciously Large EtherNet/IP UDP Packets
    description: Detects UDP packets with unusually large lengths, which could indicate an attempt to exploit CVE-2020-37216.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - zeek
  - title: Detect EtherNet/IP Traffic to HiOS Devices
    description: Detects EtherNet/IP traffic to devices which may be HiOS devices, indicating potential exploitation attempts.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1018
    data_sources:
      - network_connection
      - zeek
rules_count: 2
---

Hirschmann HiOS is vulnerable to a denial-of-service (DoS) condition due to improper handling of packet length fields within the EtherNet/IP stack. This vulnerability, identified as CVE-2020-37216, affects HiOS devices with versions prior to 08.1.00 and 07.1.01. A remote attacker can exploit this flaw by sending specially crafted UDP EtherNet/IP packets where the specified length value exceeds the actual packet size. Successful exploitation leads to a device crash or hang, rendering it inoperable and disrupting network communications. This vulnerability was reported and published in April 2026. Defenders should prioritize patching or mitigating this vulnerability to maintain network availability.

## Attack Chain

1.  Attacker identifies vulnerable Hirschmann HiOS device on the network.
2.  Attacker crafts a malicious UDP EtherNet/IP packet.
3.  The crafted packet includes a length field with a value exceeding the actual packet size.
4.  The attacker sends the crafted UDP EtherNet/IP packet to the targeted HiOS device.
5.  The HiOS device attempts to process the malformed packet.
6.  Due to the improper handling of the invalid length field, the EtherNet/IP stack within the HiOS device encounters an error.
7.  The error causes the HiOS device to crash or hang.
8.  The device becomes inoperable, resulting in a denial-of-service condition.

## Impact

Successful exploitation of CVE-2020-37216 results in a denial-of-service condition on the affected Hirschmann HiOS device. This can disrupt critical network communications and potentially impact industrial control systems relying on the affected device. The number of affected devices and organizations depends on the prevalence of vulnerable HiOS versions within operational networks. A successful attack could lead to temporary or prolonged outages, impacting productivity and availability of industrial processes.

## Recommendation

*   Upgrade Hirschmann HiOS devices to versions 08.1.00 or 07.1.01 or later to patch CVE-2020-37216.
*   Monitor network traffic for suspicious UDP EtherNet/IP packets with abnormally large length fields destined for Hirschmann HiOS devices, using the provided Sigma rule.
*   Implement network segmentation to limit the potential impact of a successful denial-of-service attack.
*   Review and harden the configuration of Hirschmann HiOS devices according to vendor best practices.
