---
title: Dnsmasq Out-of-Bounds Write Vulnerability (CVE-2026-6507)
slug: 2026-04-dnsmasq-dos
description: A remote attacker can exploit an out-of-bounds write vulnerability (CVE-2026-6507) in dnsmasq by sending a specially crafted BOOTREPLY packet to a server configured with the `--dhcp-split-relay` option, leading to a denial of service.
date: "2026-04-17T13:16:14Z"
severities:
  - high
tags:
  - dnsmasq
  - denial-of-service
  - cve-2026-6507
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
cves:
  - id: CVE-2026-6507
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6507
  - https://access.redhat.com/security/cve/CVE-2026-6507
  - https://bugzilla.redhat.com/show_bug.cgi?id=2459181
rules:
  - title: Detect Malformed BOOTREPLY Packets
    description: Detects suspicious BOOTREPLY packets that may be crafted to exploit CVE-2026-6507
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - linux
  - title: Detect Dnsmasq Process Crash
    description: Detects dnsmasq process crashes, which could indicate exploitation of CVE-2026-6507
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-6507 is an out-of-bounds write vulnerability affecting dnsmasq. The vulnerability is triggered when a dnsmasq server is configured with the `--dhcp-split-relay` option and receives a specially crafted BOOTREPLY packet from a remote attacker. Successful exploitation results in memory corruption, causing the dnsmasq daemon to crash and leading to a denial of service (DoS) condition. This vulnerability poses a significant threat to organizations relying on dnsmasq for DNS and DHCP…
