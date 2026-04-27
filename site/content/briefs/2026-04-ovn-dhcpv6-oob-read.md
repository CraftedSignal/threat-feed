---
title: OVN DHCPv6 Out-of-Bounds Read Vulnerability (CVE-2026-5367)
slug: 2026-04-ovn-dhcpv6-oob-read
description: A remote attacker can exploit an out-of-bounds read vulnerability in Open Virtual Network (OVN) by sending crafted DHCPv6 SOLICIT packets, leading to sensitive information disclosure.
date: "2026-04-24T13:16:21Z"
severities:
  - high
tags:
  - cve
  - vulnerability
  - network
vendors:
  - Open Virtual Network
products:
  - OVN
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1588
    technique_name: Obtain Capabilities
cves:
  - id: CVE-2026-5367
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5367
rules:
  - title: Detect Suspicious DHCPv6 SOLICIT Packets with Long Client ID
    description: Detects DHCPv6 SOLICIT packets with unusually long Client ID lengths, potentially indicating an attempt to exploit CVE-2026-5367.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1588.006
    data_sources:
      - network_connection
      - linux
  - title: Detect ovn-controller Process Crash Related to DHCPv6 Processing
    description: Detects ovn-controller process crashes potentially related to DHCPv6 processing, which could be caused by CVE-2026-5367.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1588.006
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-5367 describes a critical vulnerability affecting Open Virtual Network (OVN). A remote attacker can exploit this flaw by sending specially crafted DHCPv6 SOLICIT packets to the OVN controller. These packets contain an inflated Client ID length, which causes the `ovn-controller` process to read beyond the allocated memory buffer. This out-of-bounds read allows the attacker to potentially access sensitive information stored in the heap memory, which can then be disclosed back to the…
