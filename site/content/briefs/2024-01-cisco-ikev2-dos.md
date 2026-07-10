---
title: Cisco IKEv2 Memory Leak Vulnerability (CVE-2026-20012)
slug: 2024-01-cisco-ikev2-dos
description: CVE-2026-20012 is a vulnerability in the IKEv2 feature of multiple Cisco products that allows an unauthenticated remote attacker to cause a denial of service by sending crafted IKEv2 packets leading to memory exhaustion.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-20012
  - denial-of-service
  - cisco
  - ikev2
vendors:
  - Cisco
products:
  - Cisco IOS Software
  - Cisco IOS XE Software
  - Cisco Secure Firewall Adaptive Security Appliance (ASA) Software
  - Cisco Secure Firewall Threat Defense (FTD) Software
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20012
rules:
  - title: Detect Suspicious IKEv2 Traffic
    description: Detects potentially malicious IKEv2 traffic based on unusual packet size, which might indicate exploitation attempts of CVE-2026-20012
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.002
    data_sources:
      - network_connection
      - cisco
  - title: Detect Multiple Connections to IKEV2 Port from Single IP
    description: Detects potential DOS attack by monitoring number of connections initiated towards IKEV2 Ports from Single Source IP
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.002
    data_sources:
      - network_connection
      - cisco
rules_count: 2
---

CVE-2026-20012 affects the Internet Key Exchange version 2 (IKEv2) implementation in Cisco IOS Software, Cisco IOS XE Software, Cisco Secure Firewall Adaptive Security Appliance (ASA) Software, and Cisco Secure Firewall Threat Defense (FTD) Software. Published in March 2026, the vulnerability stems from the improper parsing of IKEv2 packets. An unauthenticated, remote attacker can exploit this flaw by sending crafted IKEv2 packets to a vulnerable device. Successful exploitation leads to a memory leak, resulting in a denial-of-service (DoS) condition. For IOS and IOS XE Software, this manifests as a device reload, while ASA and FTD Software experience partial exhaustion of system memory, leading to instability and the inability to establish new IKEv2 VPN sessions. Recovery requires a manual reboot. This vulnerability poses a significant threat to network availability and security.

## Attack Chain

1.  The attacker identifies a vulnerable Cisco device running IKEv2.
2.  The attacker crafts malicious IKEv2 packets designed to exploit the parsing vulnerability.
3.  The attacker sends the crafted IKEv2 packets to the target device over UDP port 500 or 4500, the standard ports for IKEv2.
4.  The vulnerable device improperly parses the malicious IKEv2 packets.
5.  The improper parsing triggers a memory leak within the IKEv2 process.
6.  The memory leak gradually consumes available system memory.
7.  On Cisco IOS and IOS XE Software, the device reaches a critical memory threshold, causing a system reload and a DoS condition.
8.  On Cisco ASA and FTD Software, the memory exhaustion leads to system instability, preventing the establishment of new IKEv2 VPN sessions and requiring a manual reboot to recover.

## Impact

A successful exploit of CVE-2026-20012 can lead to significant disruption of network services. Cisco IOS and IOS XE devices may experience complete outages due to device reloads, affecting all services reliant on those devices. Cisco ASA and FTD devices will suffer degraded performance and an inability to establish new VPN connections, impacting remote access and secure communication. The necessity of a manual reboot for recovery prolongs the downtime and requires administrative intervention. The vulnerability has a CVSS v3.1 base score of 8.6, highlighting its severity.

## Recommendation

*   Upgrade Cisco IOS Software and IOS XE Software to patched versions to prevent device reloads (Refer to Cisco advisory for specific versions and patch information).
*   Upgrade Cisco Secure Firewall ASA Software and Cisco Secure Firewall Threat Defense (FTD) Software to patched versions to prevent system instability and memory exhaustion (Refer to Cisco advisory for specific versions and patch information).
*   Monitor network traffic for suspicious IKEv2 packets originating from untrusted sources, focusing on unusual packet structures or sizes (Enable network connection logging and deploy the "Detect Suspicious IKEv2 Traffic" Sigma rule).
*   Implement rate limiting for IKEv2 traffic to mitigate the impact of potential exploits (Consult your Cisco device documentation for rate limiting configuration).
