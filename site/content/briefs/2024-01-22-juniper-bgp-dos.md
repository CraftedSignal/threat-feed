---
title: Juniper Junos OS and Junos OS Evolved BGP Session Reset Denial of Service (CVE-2026-33797)
slug: 2024-01-22-juniper-bgp-dos
description: CVE-2026-33797 is an improper input validation vulnerability in Juniper Networks Junos OS and Junos OS Evolved that allows an unauthenticated adjacent attacker to reset established BGP sessions via a specific BGP packet, leading to a denial of service condition.
date: "2026-04-09T22:16:29Z"
severities:
  - medium
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

CVE-2026-33797 is a vulnerability affecting Juniper Networks Junos OS and Junos OS Evolved versions 25.2 before 25.2R2 and 25.2-EVO before 25.2R2-EVO, respectively. It stems from improper input validation within the Border Gateway Protocol (BGP) handling. An unauthenticated, adjacent attacker can exploit this flaw by sending a crafted BGP packet to an already established BGP session. This malicious packet causes the targeted BGP session to reset, leading to a Denial of Service (DoS). Repeated…
