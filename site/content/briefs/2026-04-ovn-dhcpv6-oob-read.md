---
title: OVN DHCPv6 Out-of-Bounds Read Vulnerability (CVE-2026-5367)
slug: 2026-04-ovn-dhcpv6-oob-read
description: A remote attacker can exploit an out-of-bounds read vulnerability in Open Virtual Network (OVN) by sending crafted DHCPv6 SOLICIT packets, leading to sensitive information disclosure.
date: "2026-04-24T13:16:21Z"
type: coverage
types:
  - coverage
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

CVE-2026-5367 describes a critical vulnerability affecting Open Virtual Network (OVN). A remote attacker can exploit this flaw by sending specially crafted DHCPv6 SOLICIT packets to the OVN controller. These packets contain an inflated Client ID length, which causes the `ovn-controller` process to read beyond the allocated memory buffer. This out-of-bounds read allows the attacker to potentially access sensitive information stored in the heap memory, which can then be disclosed back to the attacker's virtual machine port. Successful exploitation grants unauthorized access to potentially sensitive data within the OVN environment, impacting confidentiality.

## Attack Chain

1.  Attacker identifies a vulnerable OVN deployment.
2.  Attacker crafts a malicious DHCPv6 SOLICIT packet. The packet includes an inflated Client ID length field.
3.  The attacker sends the crafted DHCPv6 SOLICIT packet to the OVN controller.
4.  The `ovn-controller` receives the packet and attempts to process the DHCPv6 Client ID option.
5.  Due to the inflated Client ID length, the `ovn-controller` reads beyond the bounds of the allocated memory buffer.
6.  This out-of-bounds read accesses sensitive information residing in the heap memory.
7.  The compromised data is included in the DHCPv6 response sent back to the attacker's virtual machine port.
8.  Attacker receives the DHCPv6 response containing the disclosed sensitive information.

## Impact

Successful exploitation of CVE-2026-5367 leads to the disclosure of sensitive information stored in the heap memory of the `ovn-controller`. The attacker can potentially gain access to configuration data, cryptographic keys, or other sensitive data, allowing them to further compromise the OVN environment or gain unauthorized access to other resources within the network.

## Recommendation

*   Monitor network traffic for suspicious DHCPv6 SOLICIT packets with unusually long Client ID lengths targeting the OVN controller, utilizing the network_connection rule provided below.
*   Analyze DHCPv6 server logs for errors related to invalid Client ID lengths or out-of-bounds memory access, leveraging the linux process_creation rule provided below if auditd captures such events.
*   Apply any available patches or updates provided by the OVN project to address CVE-2026-5367.
