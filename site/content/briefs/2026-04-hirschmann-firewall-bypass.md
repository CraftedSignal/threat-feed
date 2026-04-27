---
title: Hirschmann HiLCOS OpenBAT/BAT450 IPv6 IPsec Firewall Bypass (CVE-2021-4477)
slug: 2026-04-hirschmann-firewall-bypass
description: CVE-2021-4477 describes a firewall bypass vulnerability in Hirschmann HiLCOS OpenBAT and BAT450 products that can be exploited by establishing IPv6 IPsec connections (IKEv1 or IKEv2) while using an IPv6 Internet connection, allowing attackers to bypass configured firewall rules.
date: "2026-04-03T23:17:01Z"
severities:
  - critical
tags:
  - cve-2021-4477
  - firewall-bypass
  - network
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
cves:
  - id: CVE-2021-4477
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-4477
  - https://assets.belden.com/m/5fd1a50fa50cb252/original/Belden-Security-Bulletin-BSECV-1v0-2019-09.pdf
  - https://www.vulncheck.com/advisories/hirschmann-hilcos-openbat-bat450-ipv6-ipsec-firewall-bypass
rules:
  - title: Detect Hirschmann IPsec Bypass
    description: Detects network connections indicative of CVE-2021-4477 exploitation on Hirschmann devices by monitoring for IKEv1 or IKEv2 traffic in conjunction with IPv6 Internet connections.
    platform: sigma
    severity: critical
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - network_connection
      - firewall
  - title: Detect High Volume of IPv6 Connections to Port 500
    description: This rule identifies a high volume of IPv6 connections being established to port 500, which could indicate an attacker attempting to exploit CVE-2021-4477 by establishing numerous IPsec connections to bypass firewall rules on vulnerable Hirschmann devices.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - network_connection
      - firewall
rules_count: 2
---

Hirschmann HiLCOS OpenBAT and BAT450 products are vulnerable to a firewall bypass (CVE-2021-4477) in IPv6 IPsec deployments. The vulnerability allows attackers to circumvent configured firewall rules by establishing IPv6 IPsec connections (IKEv1 or IKEv2) while simultaneously maintaining an IPv6 Internet connection. This bypass can allow unauthorized access to internal network resources. The vulnerability was published in April 2026. Exploitation of this vulnerability can lead to significant…
