---
title: Hirschmann HiOS EtherNet/IP Stack Denial-of-Service Vulnerability (CVE-2020-37216)
slug: 2026-04-hios-dos
description: A denial-of-service vulnerability in Hirschmann HiOS devices allows remote attackers to crash or hang the device by sending crafted UDP EtherNet/IP packets with invalid length fields.
date: "2026-04-03T21:17:08Z"
severities:
  - high
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

Hirschmann HiOS is vulnerable to a denial-of-service (DoS) condition due to improper handling of packet length fields within the EtherNet/IP stack. This vulnerability, identified as CVE-2020-37216, affects HiOS devices with versions prior to 08.1.00 and 07.1.01. A remote attacker can exploit this flaw by sending specially crafted UDP EtherNet/IP packets where the specified length value exceeds the actual packet size. Successful exploitation leads to a device crash or hang, rendering it…
