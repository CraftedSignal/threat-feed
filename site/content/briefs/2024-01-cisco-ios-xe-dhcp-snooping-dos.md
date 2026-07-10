---
title: Cisco IOS XE DHCP Snooping BOOTP VLAN Leakage DoS (CVE-2026-20084)
slug: 2024-01-cisco-ios-xe-dhcp-snooping-dos
description: CVE-2026-20084 describes a vulnerability in Cisco IOS XE DHCP snooping where an unauthenticated remote attacker can cause a denial-of-service by forwarding BOOTP packets between VLANs, leading to high CPU utilization on affected Cisco Catalyst 9000 Series Switches.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-20084
  - dhcp-snooping
  - bootp
  - denial-of-service
  - cisco
vendors:
  - Cisco
products:
  - Cisco IOS XE Software
  - Cisco Catalyst 9000 Series Switches
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20084
rules:
  - title: Detect BOOTP Traffic Between VLANs
    description: Detects BOOTP traffic being forwarded between VLANs, which may indicate exploitation of CVE-2026-20084.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - cisco
  - title: Detect High CPU Utilization After BOOTP Traffic
    description: Detects high CPU utilization on Cisco devices following BOOTP traffic, which could be a sign of CVE-2026-20084 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - firewall
      - cisco
rules_count: 2
---

CVE-2026-20084 is a vulnerability affecting the DHCP snooping feature within Cisco IOS XE Software, specifically impacting Cisco Catalyst 9000 Series Switches. This vulnerability allows an unauthenticated, remote attacker to exploit improper handling of BOOTP packets. By sending either unicast or broadcast BOOTP request packets, an attacker can trigger the forwarding of BOOTP packets between different VLANs. This cross-VLAN forwarding, or "BOOTP VLAN leakage," can result in elevated CPU utilization, rendering the device unreachable through console or remote management interfaces. The ultimate impact is a denial-of-service (DoS) condition, preventing the affected switch from forwarding network traffic and disrupting network services. The vulnerability stems from how the Cisco IOS XE software processes BOOTP packets when DHCP snooping is enabled.

## Attack Chain

1.  The attacker identifies a vulnerable Cisco Catalyst 9000 Series Switch running Cisco IOS XE with DHCP snooping enabled.
2.  The attacker crafts a malicious BOOTP request packet. This packet can be either a unicast or broadcast BOOTP request.
3.  The attacker sends the malicious BOOTP request packet to the targeted switch.
4.  The vulnerable DHCP snooping feature improperly processes the BOOTP request.
5.  Due to the improper handling, the switch forwards the BOOTP packet to an unintended VLAN.
6.  This BOOTP VLAN leakage contributes to increased CPU utilization on the switch.
7.  The high CPU utilization degrades the switch's performance, impacting its ability to forward network traffic.
8.  The switch becomes unresponsive, leading to a denial-of-service condition, disrupting network services for connected devices.

## Impact

Successful exploitation of CVE-2026-20084 leads to a denial-of-service condition on affected Cisco Catalyst 9000 Series Switches. This DoS can disrupt network services, causing connectivity issues for users and applications relying on the compromised switch. The high CPU utilization makes the device unreachable for management, complicating recovery efforts. While the exact number of potential victims is unknown, any organization using vulnerable Cisco Catalyst 9000 Series Switches is at risk. The network downtime caused by this vulnerability can lead to financial losses and reputational damage.

## Recommendation

*   Monitor network traffic for unusual BOOTP packet activity, specifically looking for packets being forwarded between VLANs, using a network intrusion detection system (IDS) and the `network_connection` log source.
*   Deploy the Sigma rule provided to detect BOOTP packets being forwarded between VLANs, and tune the rule for your specific environment.
*   Implement workarounds provided by Cisco to mitigate the vulnerability until a patch can be applied (reference the Cisco advisory for specific workaround details).
